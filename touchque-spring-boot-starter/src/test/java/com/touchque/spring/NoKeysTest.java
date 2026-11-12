package com.touchque.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.touchque.internal.Json;
import example.nokeys.NoKeysApp;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/** No TQ_API_KEY / TQ_API_SECRET: the app starts, and a guarded method answers JSON and never runs. */
@SpringBootTest(classes = NoKeysApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"touchque.api-key=", "touchque.api-secret=", "touchque.debug=true"})
class NoKeysTest {
    private static final String NOT_SET = "SEVERE [Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.";
    private final HttpClient http = HttpClient.newHttpClient();

    @LocalServerPort
    int port;

    private HttpResponse<String> pay(Map<String, String> headers) throws Exception {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/pay")).POST(HttpRequest.BodyPublishers.noBody());
        headers.forEach(req::header);
        return http.send(req.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void aGuardedMethodAnswers500MisconfiguredAndNeverRuns() throws Exception {
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
            HttpResponse<String> anonymous = pay(Map.of());
            assertEquals(401, anonymous.statusCode());
            assertEquals(Json.parse("{\"touchque\":{\"state\":\"blocked\",\"reason\":\"unauthenticated\"},\"error\":{\"code\":\"unauthenticated\",\"message\":\"Sign in first.\"}}"),
                    Json.parse(anonymous.body()));
            for (int i = 0; i < 2; i++) {
                HttpResponse<String> res = pay(Map.of("X-Test-User", "jane@acme.com"));
                assertEquals(500, res.statusCode());
                assertEquals("no-store", res.headers().firstValue("Cache-Control").orElse(null));
                assertEquals(List.of("blocked", "misconfigured"), List.of(res.headers().firstValue("X-Touchque-State").orElse(""),
                        res.headers().firstValue("X-Touchque-Reason").orElse("")));
                assertEquals(Json.parse("{\"touchque\":{\"state\":\"blocked\",\"reason\":\"misconfigured\"},"
                        + "\"error\":{\"code\":\"misconfigured\",\"message\":\"Two-factor approval is not configured correctly.\"}}"), Json.parse(res.body()));
            }
            assertEquals(0, NoKeysApp.RUNS.get());
            // Once per process, through the SDK's logger (touchque.debug).
            assertEquals(List.of(NOT_SET), lines);
        } finally {
            jul.removeHandler(handler);
            jul.setUseParentHandlers(parents);
        }
    }
}
