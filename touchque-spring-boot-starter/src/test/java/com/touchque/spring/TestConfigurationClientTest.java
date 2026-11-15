package com.touchque.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.touchque.TouchqueClient;
import com.touchque.TouchqueOptions;
import com.touchque.internal.Json;
import example.nokeys.NoKeysApp;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

/**
 * The README's second way to test with the starter: an {@code @Import}ed {@code @TestConfiguration} with your own
 * TouchqueClient bean replaces the starter's, with no touchque.* keys at all ({@link StarterTest} shows the first:
 * touchque.base-url and the keys through {@code @DynamicPropertySource}).
 */
@SpringBootTest(classes = NoKeysApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"touchque.api-key=", "touchque.api-secret="})
@Import(TestConfigurationClientTest.FakeApiClient.class)
class TestConfigurationClientTest {
    private static final FakeApi API = FakeApi.get();
    private final HttpClient http = HttpClient.newHttpClient();

    @LocalServerPort
    int port;

    @TestConfiguration(proxyBeanMethods = false)
    static class FakeApiClient {
        @Bean
        TouchqueClient fakeApiClient() {
            return new TouchqueClient(new TouchqueOptions().apiKey("tq_test_key").apiSecret("test_secret").baseUrl(API.baseUrl));
        }
    }

    @Test
    void anImportedTestConfigurationClientBeanReplacesTheStarters() throws Exception {
        API.post("/__test/reset", Map.of());
        API.post("/__test/link", Map.of("user", "jane@acme.com"));
        HttpResponse<String> res = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/pay")).header("X-Test-User", "jane@acme.com")
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
        // The step from the fake API, not 500 misconfigured: the guard used this bean.
        assertEquals(List.of(202, "waiting"), List.of(res.statusCode(), Json.parse(res.body()).get("touchque").get("state").asText()));
        assertEquals(0, NoKeysApp.RUNS.get());
    }
}
