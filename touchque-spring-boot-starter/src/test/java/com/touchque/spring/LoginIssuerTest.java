package com.touchque.spring;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.sun.net.httpserver.HttpServer;
import com.touchque.internal.Json;
import example.login.LoginApp;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * RFC 9207 at the sign-in callback: iss is checked before Spring Security exchanges the code, against
 * a tenant on this machine whose token endpoint counts the calls (and refuses every code).
 */
@SpringBootTest(classes = LoginApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class LoginIssuerTest {
    private static final AtomicInteger TOKEN_CALLS = new AtomicInteger();
    private static final HttpServer TENANT = tenant();

    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("touchque.login.domain", LoginIssuerTest::issuer);
        registry.add("touchque.login.client-id", () -> "client-123");
    }

    @AfterAll
    static void stop() {
        TENANT.stop(0);
    }

    private static String issuer() {
        return "http://127.0.0.1:" + TENANT.getAddress().getPort();
    }

    private static HttpServer tenant() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/oauth/token", ex -> {
                TOKEN_CALLS.incrementAndGet();
                byte[] body = "{\"error\":\"invalid_grant\"}".getBytes(UTF_8);
                ex.getResponseHeaders().set("Content-Type", "application/json");
                ex.sendResponseHeaders(400, body.length);
                ex.getResponseBody().write(body);
                ex.close();
            });
            server.start();
            return server;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private HttpResponse<String> get(String path, String cookie) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path));
        if (cookie != null) request.header("Cookie", cookie);
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Starts a sign-in: {session cookie, state}. */
    private String[] start() throws Exception {
        HttpResponse<String> started = get("/oauth2/authorization/touchque", null);
        String location = started.headers().firstValue("Location").orElseThrow();
        String state = null;
        for (String part : location.substring(location.indexOf('?') + 1).split("&")) {
            if (part.startsWith("state=")) state = URLDecoder.decode(part.substring(6), UTF_8);
        }
        return new String[] {started.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0], state};
    }

    private HttpResponse<String> callback(String[] signIn, String fields) throws Exception {
        return get("/login/oauth2/code/touchque?state=" + URLEncoder.encode(signIn[1], UTF_8) + "&" + fields, signIn[0]);
    }

    private static String iss(String value) {
        return "iss=" + URLEncoder.encode(value, UTF_8);
    }

    @Test
    void aForeignOrEmptyIssIsRefusedBeforeTheCodeExchangeAndEndsThatSignIn() throws Exception {
        int before = TOKEN_CALLS.get();
        for (String foreign : List.of("https://evil", issuer() + "/", "")) {
            String[] signIn = start();
            HttpResponse<String> back = callback(signIn, "code=c&" + iss(foreign));
            assertEquals(400, back.statusCode(), foreign);
            assertEquals("issuer_mismatch", Json.parse(back.body()).get("error").asText());
            // That sign-in is over: the same state with the right iss finds nothing to finish.
            assertEquals(302, callback(signIn, "code=c&" + iss(issuer())).statusCode());
        }
        // A foreign error answer is refused as the issuer mismatch too.
        assertEquals(400, callback(start(), "error=access_denied&" + iss("https://evil")).statusCode());
        assertEquals(before, TOKEN_CALLS.get());
    }

    @Test
    void thisIssuersIssOrNoneGoesOnToTheCodeExchange() throws Exception {
        int before = TOKEN_CALLS.get();
        assertEquals(302, callback(start(), "code=c&" + iss(issuer())).statusCode());
        assertEquals(before + 1, TOKEN_CALLS.get());
        // No iss: a server that does not send it yet.
        assertEquals(302, callback(start(), "code=c").statusCode());
        assertEquals(before + 2, TOKEN_CALLS.get());
    }
}
