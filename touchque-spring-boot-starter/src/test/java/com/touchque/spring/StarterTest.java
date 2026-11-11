package com.touchque.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import com.touchque.resources.Webhook;
import example.app.TestApp;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** The starter in a running app against the shared fake API: guard, relay, webhooks and MCP. */
@SpringBootTest(classes = TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("open")
class StarterTest {
    private static final String RESOURCE = "https://mcp.acme.example/mcp";
    private static final FakeApi API = FakeApi.get();
    private final HttpClient http = HttpClient.newHttpClient();

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        r.add("touchque.api-key", () -> "tq_test_key");
        r.add("touchque.api-secret", () -> "test_secret");
        r.add("touchque.base-url", () -> API.baseUrl);
        r.add("touchque.mcp.issuer", () -> API.baseUrl + "/mcp-as");
        r.add("touchque.mcp.resource", () -> RESOURCE);
        r.add("touchque.mcp.tools.search_tickets", () -> "tickets:read");
        r.add("touchque.mcp.tools.delete_ticket", () -> "tickets:delete");
    }

    @BeforeEach
    void reset() throws Exception {
        API.post("/__test/reset", Map.of());
        API.post("/__test/link", Map.of("user", "jane@acme.com"));
        TestApp.EVENTS.clear();
        TestApp.FAIL_NEXT_EVENT.set(false);
    }

    private HttpResponse<String> send(String method, String path, Object body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(body instanceof String s ? s : Json.write(Json.toNode(body))));
        if (body != null) req.header("Content-Type", "application/json");
        headers.forEach(req::header);
        return http.send(req.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void requireTouchqueWaitsForThePhoneThenRunsOnce() throws Exception {
        HttpResponse<String> first = send("POST", "/transfer", Map.of("amount", "250 EUR"), Map.of());
        assertEquals(202, first.statusCode());
        assertEquals("no-store", first.headers().firstValue("Cache-Control").orElse(null));
        JsonNode step = Json.parse(first.body());
        assertEquals(List.of("waiting", "47"), List.of(step.get("touchque").get("state").asText(), step.get("touchque").get("number").asText()));
        JsonNode calls = API.get("/__test/calls");
        assertEquals(Json.parse("[{\"label\":\"Amount\",\"value\":\"250 EUR\"}]"), calls.get(calls.size() - 1).get("body").get("details"));
        String token = step.get("token").asText();
        assertEquals(202, send("POST", "/transfer", Map.of("amount", "250 EUR"), Map.of("X-Touchque-Token", token)).statusCode());
        API.post("/__test/approve", Map.of("via", "DEVICE"));
        HttpResponse<String> done = send("POST", "/transfer", Map.of("amount", "250 EUR"), Map.of("X-Touchque-Token", token));
        assertEquals(200, done.statusCode());
        assertEquals(Json.parse("{\"ok\":true,\"amount\":\"250 EUR\",\"via\":\"push\"}"), Json.parse(done.body()));
        int replay = send("POST", "/transfer", Map.of("amount", "250 EUR"), Map.of("X-Touchque-Token", token)).statusCode();
        assertTrue(List.of(403, 408, 409).contains(replay), "replay answered " + replay);
        // A token is bound to the details it was approved with.
        assertEquals(202, send("POST", "/transfer", Map.of("amount", "9999 EUR"), Map.of("X-Touchque-Token", token)).statusCode());

        API.post("/__test/opts", Map.of("frozen", true));
        HttpResponse<String> frozen = send("POST", "/transfer", Map.of("amount", "1 EUR"), Map.of());
        assertEquals(423, frozen.statusCode());
        assertEquals("900", frozen.headers().firstValue("Retry-After").orElse(null));
    }

    @Test
    void relayRoutes() throws Exception {
        HttpResponse<String> login = send("POST", "/touchque/login", Map.of(), Map.of("X-Test-User", "jane@acme.com"));
        assertEquals(202, login.statusCode(), login.body());
        String token = Json.parse(login.body()).get("token").asText();
        API.post("/__test/approve", Map.of("via", "DEVICE"));
        HttpResponse<String> done = send("POST", "/touchque/login", Map.of(), Map.of("X-Test-User", "jane@acme.com", "X-Touchque-Token", token));
        assertEquals(200, done.statusCode(), done.body());
        assertEquals("jane@acme.com", done.headers().firstValue("X-Signed-In").orElse(null));
        assertEquals(404, send("POST", "/touchque/nope", Map.of(), Map.of()).statusCode());
        assertEquals(400, send("POST", "/touchque/login", "{not json", Map.of("X-Test-User", "jane@acme.com")).statusCode());
    }

    private static String signed(ObjectNode payload) {
        payload.put("signature", Crypto.hmacHex("test_secret", Webhook.canonicalize(Json.write(payload))));
        return Json.write(payload);
    }

    @Test
    void webhooksAreVerifiedOnce() throws Exception {
        String body = signed(Json.object().put("event", "APPROVAL_REVOKED").put("requestId", "r1").put("timestamp", Instant.now().toString()).put("jti", "j-" + System.nanoTime()));
        HttpResponse<String> ok = send("POST", "/webhooks/touchque", body, Map.of());
        assertEquals(200, ok.statusCode());
        assertEquals(Json.parse("{\"received\":true}"), Json.parse(ok.body()));
        assertEquals("r1", TestApp.EVENTS.get(0).get("requestId").asText());
        assertEquals(Json.parse("{\"received\":true,\"duplicate\":true}"), Json.parse(send("POST", "/webhooks/touchque", body, Map.of()).body()));
        assertEquals(1, TestApp.EVENTS.size());
        assertEquals(401, send("POST", "/webhooks/touchque", body.replace("\"r1\"", "\"r2\""), Map.of()).statusCode());
        assertEquals(405, send("GET", "/webhooks/touchque", null, Map.of()).statusCode());
    }

    @Test
    void aWebhookTheListenerFailedOnRunsAgainWhenRetried() throws Exception {
        String body = signed(Json.object().put("event", "APPROVAL_REVOKED").put("requestId", "r3").put("timestamp", Instant.now().toString()).put("jti", "j-" + System.nanoTime()));
        TestApp.FAIL_NEXT_EVENT.set(true);
        assertEquals(500, send("POST", "/webhooks/touchque", body, Map.of()).statusCode());
        assertEquals(0, TestApp.EVENTS.size());
        // Touchque retries the same delivery (same jti): it is not a duplicate, the listener runs.
        HttpResponse<String> retry = send("POST", "/webhooks/touchque", body, Map.of());
        assertEquals(Json.parse("{\"received\":true}"), Json.parse(retry.body()));
        assertEquals("r3", TestApp.EVENTS.get(0).get("requestId").asText());
        assertEquals(Json.parse("{\"received\":true,\"duplicate\":true}"), Json.parse(send("POST", "/webhooks/touchque", body, Map.of()).body()));
        assertEquals(1, TestApp.EVENTS.size());
    }

    private String mcpToken(String scope) throws Exception {
        return API.post("/__test/mcp-token", Map.of("aud", RESOURCE, "scope", scope)).get("token").asText();
    }

    @Test
    void mcpMetadataTokensAndTools() throws Exception {
        HttpResponse<String> meta = send("GET", "/.well-known/oauth-protected-resource/mcp", null, Map.of());
        assertEquals(200, meta.statusCode());
        assertEquals(RESOURCE, Json.parse(meta.body()).get("resource").asText());
        HttpResponse<String> none = send("POST", "/mcp", Map.of("tool", "search_tickets"), Map.of());
        assertEquals(401, none.statusCode());
        assertEquals("Bearer resource_metadata=\"https://mcp.acme.example/.well-known/oauth-protected-resource/mcp\"", none.headers().firstValue("WWW-Authenticate").orElse(null));
        String token = mcpToken("tickets:read");
        HttpResponse<String> ok = send("POST", "/mcp", Map.of("tool", "search_tickets"), Map.of("Authorization", "Bearer " + token));
        assertEquals(200, ok.statusCode(), ok.body());
        assertEquals("user-1", Json.parse(ok.body()).get("sub").asText());
        HttpResponse<String> denied = send("POST", "/mcp", Map.of("tool", "delete_ticket"), Map.of("Authorization", "Bearer " + token));
        assertEquals(403, denied.statusCode());
        assertTrue(denied.headers().firstValue("WWW-Authenticate").orElse("").contains("scope=\"tickets:delete\""));
    }
}
