package com.touchque.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.touchque.TouchqueClient;
import com.touchque.TouchqueOptions;
import com.touchque.internal.Json;
import com.touchque.resources.Auth;
import example.app.TestApp;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.DynamicPropertyRegistry;

/**
 * Behind a proxy the container trusts ({@code server.forward-headers-strategy=native}: Tomcat's
 * RemoteIpValve, 127.0.0.1 an internal proxy), the starter sends the push and the first-time QR the
 * same address: the rightmost X-Forwarded-For entry that is not a proxy, never the leftmost one,
 * which the browser can set itself.
 */
@SpringBootTest(classes = TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "server.forward-headers-strategy=native")
@ActiveProfiles("open")
class ForwardedClientIpTest {
    private static final FakeApi API = FakeApi.get();
    private static final String WINDOWS_FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0";
    private final HttpClient http = HttpClient.newHttpClient();

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        r.add("touchque.api-key", () -> "tq_test_key");
        r.add("touchque.api-secret", () -> "test_secret");
        r.add("touchque.base-url", () -> API.baseUrl);
        r.add("touchque.mcp.issuer", () -> API.baseUrl + "/mcp-as");
        r.add("touchque.mcp.resource", () -> "https://mcp.acme.example/mcp");
    }

    private HttpResponse<String> post(String path, Map<String, String> headers) throws Exception {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{}"));
        headers.forEach(req::header);
        return http.send(req.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static List<String> ipAndUa(JsonNode body) {
        return Arrays.asList(Json.str(body, "clientIp"), Json.str(body, "userAgent"));
    }

    @Test
    void theQrIsAskedForFromTheAddressThePushUsesNeverTheLeftmostForwardedOne() throws Exception {
        API.post("/__test/reset", Map.of());
        TouchqueClient tq = new TouchqueClient(new TouchqueOptions().apiKey("tq_test_key").apiSecret("test_secret").baseUrl(API.baseUrl));

        // @RequireTouchque for a user with no phone.
        HttpResponse<String> guarded = post("/account", Map.of("X-Test-User", "proxied@acme.com", "User-Agent", StarterTest.IPHONE_SAFARI,
                "X-Forwarded-For", "198.51.100.99, 203.0.113.7"));
        assertEquals(List.of(202, "enroll"), List.of(guarded.statusCode(), Json.parse(guarded.body()).get("touchque").get("state").asText()));
        List<String> expected = Arrays.asList("203.0.113.7", StarterTest.IPHONE_SAFARI);
        assertEquals(expected, ipAndUa(StarterTest.bodies("/login/request").get(0)));
        assertEquals(expected, ipAndUa(StarterTest.bodies("/auth/generate-secret").get(0)));
        // The phone sees where it was asked for.
        Auth.SetupContext where = Auth.SetupContext.of(tq.auth().validateSecret("S"));
        assertEquals(List.of("203.0.113.7", new Auth.SetupLocation("Berlin", "Germany", "DE"), new Auth.SetupDevice("Safari", "iOS", "iPhone")),
                Arrays.asList(where.ip(), where.location(), where.device()));

        // The relay's /enroll/start for a signed-in user.
        HttpResponse<String> start = post("/touchque/enroll/start", Map.of("X-Test-Signed-In", "proxied-enroll@acme.com", "User-Agent", WINDOWS_FIREFOX,
                "X-Forwarded-For", "198.51.100.99, 198.51.100.23"));
        assertEquals(200, start.statusCode(), start.body());
        assertEquals(Arrays.asList("198.51.100.23", WINDOWS_FIREFOX), ipAndUa(StarterTest.bodies("/auth/generate-secret").get(1)));
        Auth.SetupContext enrolled = Auth.SetupContext.of(tq.auth().validateSecret("S"));
        assertEquals(List.of("198.51.100.23", new Auth.SetupLocation("New York", "United States", "US"), new Auth.SetupDevice("Firefox", "Windows", null)),
                Arrays.asList(enrolled.ip(), enrolled.location(), enrolled.device()));
    }
}
