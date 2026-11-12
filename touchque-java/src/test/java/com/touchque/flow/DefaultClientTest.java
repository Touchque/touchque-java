package com.touchque.flow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.touchque.Support;
import com.touchque.TouchqueClient;
import com.touchque.TouchqueConfigException;
import com.touchque.TouchqueOptions;
import java.text.MessageFormat;
import java.util.HashSet;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Guard.defaultClient(): a failed build is never kept, a good one is built once, and
 * Guard.setDefaultClient replaces or forgets it. The build goes through {@link Guard#clientBuilder},
 * so these tests do not depend on the environment.
 */
class DefaultClientTest {
    private final Support.FakeApi api = Support.FakeApi.get();

    @BeforeEach
    @AfterEach
    void forget() {
        Guard.clientBuilder = TouchqueClient::new;
        Guard.setDefaultClient(null);
    }

    @Test
    void aFailedBuildIsNotKeptAndAGoodOneIsBuiltOnceForEveryThread() throws Exception {
        api.reset();
        api.link("build@acme.com");
        AtomicInteger builds = new AtomicInteger();
        AtomicBoolean keysSet = new AtomicBoolean();
        Guard.clientBuilder = () -> {
            builds.incrementAndGet();
            if (!keysSet.get()) throw new TouchqueConfigException("Set TQ_API_KEY and TQ_API_SECRET (or apiKey and apiSecret in TouchqueOptions).");
            return api.client();
        };
        Guard.Input input = new Guard.Input("build@acme.com", "LOGIN");
        assertEquals(List.of(500, 500), List.of(Guard.run(null, input).status(), Guard.run(null, input).status()));
        // The fail-fast check at startup throws and names the problem.
        TouchqueConfigException e = assertThrows(TouchqueConfigException.class, Guard::defaultClient);
        assertTrue(e.getMessage().contains("TQ_API_KEY"), e.getMessage());
        assertEquals(3, builds.get());   // every call tried again: no failure was kept

        keysSet.set(true);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<Future<TouchqueClient>> clients = new java.util.ArrayList<>();
        for (int i = 0; i < 32; i++) clients.add(pool.submit(Guard::defaultClient));
        Set<TouchqueClient> distinct = new HashSet<>();
        for (Future<TouchqueClient> f : clients) distinct.add(f.get());
        pool.shutdown();
        assertEquals(List.of(1, 4), List.of(distinct.size(), builds.get()));
        assertEquals(202, Guard.run(null, input).status());
        assertEquals(4, builds.get());
    }

    /** A System.Logger that keeps the lines. */
    static final class Lines implements System.Logger {
        final List<String> lines = new CopyOnWriteArrayList<>();

        @Override
        public String getName() {
            return "test";
        }

        @Override
        public boolean isLoggable(Level level) {
            return true;
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String msg, Throwable thrown) {
            lines.add(msg);
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String format, Object... params) {
            lines.add(params == null || params.length == 0 ? format : MessageFormat.format(format, params));
        }
    }

    @Test
    void setDefaultClientReplacesTheNullClientAndNullForgetsIt() {
        api.reset();
        api.link("set@acme.com");
        Lines logger = new Lines();
        TouchqueClient mine = new TouchqueClient(new TouchqueOptions().apiKey("tq_test_key").apiSecret("test_secret").baseUrl(api.baseUrl).logger(logger));
        Guard.setDefaultClient(mine);
        assertSame(mine, Guard.defaultClient());
        Guard.Result first = Guard.run(null, new Guard.Input("set@acme.com", "LOGIN"));
        assertEquals(202, first.status());
        assertTrue(Guard.isStatusPoll(null, new Guard.Input("set@acme.com", "LOGIN").token(first.body().get("token").asText())));
        // A client built with a logger gives the null-client path its lines.
        assertEquals(500, Guard.run(null, new Guard.Input("set@acme.com", "NOT_DEFINED")).status());
        assertEquals(1, logger.lines.size());
        assertTrue(logger.lines.get(0).startsWith("[Touchque] guard misconfigured: ") && logger.lines.get(0).contains("Unknown action \"NOT_DEFINED\""),
                logger.lines.get(0));

        // null forgets it: the next call builds one again (from the environment; the test's builder here).
        AtomicInteger builds = new AtomicInteger();
        Guard.clientBuilder = () -> {
            builds.incrementAndGet();
            return api.client();
        };
        Guard.setDefaultClient(null);
        TouchqueClient rebuilt = Guard.defaultClient();
        assertNotSame(mine, rebuilt);
        assertEquals(1, builds.get());
        assertSame(rebuilt, Guard.defaultClient());
    }
}
