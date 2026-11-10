package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.touchque.flow.Guard;
import com.touchque.internal.Json;
import com.touchque.relay.RelayHandler;
import com.touchque.relay.RelayOptions;
import com.touchque.relay.RelayRequest;
import com.touchque.resources.LoginRequestOptions;
import java.text.MessageFormat;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.Test;

/** The SDK is silent by default: its own problems go only to the logger it is given, or to System.Logger "touchque" with debug. */
class LoggingTest {
    private final Support.FakeApi api = Support.FakeApi.get();

    /** A System.Logger that keeps "LEVEL message" lines. */
    static class ListLogger implements System.Logger {
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
            lines.add(level + " " + msg);
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String format, Object... params) {
            lines.add(level + " " + (params == null || params.length == 0 ? format : MessageFormat.format(format, params)));
        }
    }

    private TouchQueClient client(String baseUrl, TouchQueOptions options) {
        return new TouchQueClient(options.apiKey("tq_test_key").apiSecret("test_secret").baseUrl(baseUrl));
    }

    @Test
    void guardAndOnChallengeLogOnlyThroughTheLogger() {
        api.reset();
        api.link("log@acme.com");
        api.opts(Map.of("numberMatch", true));
        java.util.logging.Logger jul = java.util.logging.Logger.getLogger("touchque");
        List<String> julLines = new CopyOnWriteArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord r) {
                julLines.add(r.getLevel() + " " + r.getMessage());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        boolean parents = jul.getUseParentHandlers();
        jul.addHandler(handler);
        jul.setUseParentHandlers(false);
        try {
            assertEquals(500, Guard.run(api.client(), new Guard.Input("log@acme.com", "NOT_DEFINED")).status());
            assertEquals(List.of(), julLines); // silent by default

            ListLogger logger = new ListLogger();
            TouchQueClient tq = client(api.baseUrl, new TouchQueOptions().logger(logger).debug(true));
            assertEquals(500, Guard.run(tq, new Guard.Input("log@acme.com", "NOT_DEFINED")).status());
            assertTrue(tq.login().verify(new LoginRequestOptions("log@acme.com").timeout(Duration.ofSeconds(10)).onChallenge(c -> {
                api.approve(c.requestId());
                throw new IllegalStateException("screen gone");
            })).approved());
            assertEquals(2, logger.lines.size(), logger.lines.toString());
            assertTrue(logger.lines.get(0).startsWith("ERROR [TouchQue] guard misconfigured: TouchQueConfigException: "), logger.lines.get(0));
            assertTrue(logger.lines.get(0).contains("NOT_DEFINED"));
            assertEquals("WARNING [TouchQue] onChallenge failed: IllegalStateException: screen gone", logger.lines.get(1));
            assertEquals(List.of(), julLines); // a logger given: nothing to "touchque"

            // debug with no logger: System.Logger "touchque" (java.util.logging here).
            assertEquals(500, Guard.run(client(api.baseUrl, new TouchQueOptions().debug(true)), new Guard.Input("log@acme.com", "NOT_DEFINED")).status());
            assertEquals(1, julLines.size());
            assertTrue(julLines.get(0).startsWith("SEVERE [TouchQue] guard misconfigured: TouchQueConfigException: "), julLines.get(0));
        } finally {
            jul.removeHandler(handler);
            jul.setUseParentHandlers(parents);
        }
    }

    @Test
    void relayErrorsAndAFailedSilentSignInGoToTheLogger() throws Exception {
        try (Support.Stub stub = new Support.Stub(seen -> seen.path().startsWith("/login/request")
                ? Support.Answer.json(200, Map.of("requestId", "r1", "expiresAt", "soon"))
                : Support.Answer.json(500, Map.of("error", "boom")))) {
            ListLogger logger = new ListLogger();
            TouchQueClient tq = client(stub.baseUrl, new TouchQueOptions().logger(logger));

            RelayHandler<String> relay = new RelayHandler<>(tq, new RelayOptions<String>(req -> req));
            assertEquals(1, logger.lines.size());
            assertTrue(logger.lines.get(0).startsWith("WARNING [TouchQue] RelayHandler: POST /login takes the username from the request body; "),
                    logger.lines.get(0));
            assertEquals(502, relay.handle(new RelayRequest<>("GET", "/enroll/status", Json.object(), "203.0.113.7", "UA", h -> null, "u1")).status());
            assertEquals("ERROR [TouchQue Relay Error] TouchQueApiException (boom): boom", logger.lines.get(1));

            // The risk check fails: the guard asks the phone, and says why.
            Guard.Result r = Guard.run(tq, new Guard.Input("log@acme.com", "LOGIN").browserProof("proof").silentSignIn(Guard.SilentSignIn.on()));
            assertEquals(202, r.status());
            assertEquals(List.of("WARNING [TouchQue] silent sign-in check failed, asking the phone: TouchQueApiException (boom): boom"), logger.lines.subList(2, logger.lines.size()));
            // None of it names the user, the request or the IP.
            for (String line : logger.lines) assertTrue(!line.contains("log@acme.com") && !line.contains("u1") && !line.contains("203.0.113.7"), line);
        }
    }

    @Test
    void aLoggerThatThrowsNeverBreaksARequest() throws Exception {
        System.Logger broken = new ListLogger() {
            @Override
            public void log(Level level, ResourceBundle bundle, String format, Object... params) {
                throw new IllegalStateException("logger down");
            }

            @Override
            public void log(Level level, ResourceBundle bundle, String msg, Throwable thrown) {
                throw new IllegalStateException("logger down");
            }
        };
        try (Support.Stub stub = new Support.Stub(seen -> Support.Answer.json(500, Map.of("error", "boom")))) {
            TouchQueClient tq = client(stub.baseUrl, new TouchQueOptions().logger(broken));
            RelayHandler<String> relay = new RelayHandler<>(tq, new RelayOptions<String>(req -> req));
            assertEquals(502, relay.handle(new RelayRequest<>("GET", "/enroll/status", Json.object(), "203.0.113.7", "UA", h -> null, "u1")).status());
        }
    }
}
