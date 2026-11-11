package com.touchque.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.touchque.TouchqueClient;
import com.touchque.relay.RelayHandler;
import com.touchque.relay.RelayOptions;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.Test;

/** touchque.debug: the client bean logs the SDK's own problems to the logger "touchque"; off, it logs nothing. */
class DebugLoggingTest {
    private static TouchqueClient client(boolean debug) {
        TouchqueProperties properties = new TouchqueProperties();
        properties.setApiKey("tq_test_key");
        properties.setApiSecret("test_secret");
        properties.setDebug(debug);
        return new TouchqueAutoConfiguration().touchqueClient(properties);
    }

    @Test
    void debugLogsToTheTouchqueLoggerAndIsOffByDefault() {
        java.util.logging.Logger jul = java.util.logging.Logger.getLogger("touchque");
        List<String> lines = new CopyOnWriteArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord r) {
                lines.add(r.getLevel() + " " + r.getMessage());
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
            // A relay without getLoginUser is one of the problems the SDK reports.
            new RelayHandler<>(client(false), new RelayOptions<String>(req -> req));
            assertEquals(List.of(), lines);
            new RelayHandler<>(client(true), new RelayOptions<String>(req -> req));
            assertEquals(1, lines.size());
            assertTrue(lines.get(0).startsWith("WARNING [Touchque] RelayHandler: POST /login takes the username from the request body"), lines.get(0));
        } finally {
            jul.removeHandler(handler);
            jul.setUseParentHandlers(parents);
        }
    }
}
