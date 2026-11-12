package com.touchque.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.touchque.internal.Json;
import example.custom.CustomBeansApp;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** The app's own beans: a client bean looked up on every request, and two TouchqueErrorBody beans that never break a step. */
@SpringBootTest(classes = CustomBeansApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CustomBeansTest {
    private static final FakeApi API = FakeApi.get();
    private final HttpClient http = HttpClient.newHttpClient();

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        r.add("touchque.api-key", () -> "tq_test_key");
        r.add("touchque.api-secret", () -> "test_secret");
        r.add("touchque.base-url", () -> API.baseUrl);
    }

    private HttpResponse<String> pay(Map<String, String> headers) throws Exception {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/pay")).POST(HttpRequest.BodyPublishers.noBody());
        headers.forEach(req::header);
        return http.send(req.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void theClientBeanIsLookedUpOnEveryRequestAndTwoErrorBodiesNeverBreakAStep() throws Exception {
        API.post("/__test/reset", Map.of());
        API.post("/__test/link", Map.of("user", "jane@acme.com"));
        int before = CustomBeansApp.CLIENTS.get();
        HttpResponse<String> first = pay(Map.of("X-Test-User", "jane@acme.com"));
        assertEquals(List.of(202, "waiting"), List.of(first.statusCode(), Json.parse(first.body()).get("touchque").get("state").asText()));
        HttpResponse<String> poll = pay(Map.of("X-Test-User", "jane@acme.com", "X-Touchque-Token", Json.parse(first.body()).get("token").asText()));
        assertEquals(202, poll.statusCode());
        // A prototype (or per-tenant) client bean is not frozen to the first one.
        assertEquals(2, CustomBeansApp.CLIENTS.get() - before);
        // Two errorBody beans and none @Primary: refusals keep the default body.
        HttpResponse<String> anonymous = pay(Map.of());
        assertEquals(401, anonymous.statusCode());
        assertEquals(Json.parse("{\"touchque\":{\"state\":\"blocked\",\"reason\":\"unauthenticated\"},\"error\":{\"code\":\"unauthenticated\",\"message\":\"Sign in first.\"}}"),
                Json.parse(anonymous.body()));
    }
}
