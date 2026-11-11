package com.touchque.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Json;
import example.login.LoginApp;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/** Touchque Login through Spring Security: sign-in with PKCE from two properties, and the resource server's decoder. */
@SpringBootTest(classes = LoginApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
    "touchque.login.domain=acme.login.touchque.com", "touchque.login.client-id=client-123", "touchque.login.client-secret=s3cret",
    "touchque.login.audience=https://api.acme.test"})
class LoginTest {
    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    @LocalServerPort
    int port;

    @Autowired
    JwtDecoder jwtDecoder;

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void pagesSignInWithTouchqueUsingPkce() throws Exception {
        HttpResponse<String> page = get("/me");
        assertEquals(302, page.statusCode());
        assertTrue(page.headers().firstValue("Location").orElse("").endsWith("/oauth2/authorization/touchque"));
        HttpResponse<String> start = get("/oauth2/authorization/touchque");
        assertEquals(302, start.statusCode());
        String location = start.headers().firstValue("Location").orElse("");
        assertTrue(location.startsWith("https://acme.login.touchque.com/authorize?"), location);
        Map<String, String> q = new HashMap<>();
        for (String part : location.substring(location.indexOf('?') + 1).split("&")) {
            String[] kv = part.split("=", 2);
            q.put(kv[0], URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
        }
        assertEquals("code", q.get("response_type"));
        assertEquals("client-123", q.get("client_id"));
        assertEquals("openid profile email", q.get("scope"));
        assertEquals("S256", q.get("code_challenge_method"));
        assertEquals(43, q.get("code_challenge").length());
        assertEquals("http://127.0.0.1:" + port + "/login/oauth2/code/touchque", q.get("redirect_uri"));
        assertTrue(jwtDecoder instanceof NimbusJwtDecoder);
    }

    @Test
    void accessTokensMustBeAtJwtForThisApi() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair key = g.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) key.getPublic();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        byte[] jwks = Json.write(Json.toNode(Map.of("keys", java.util.List.of(Map.of("kty", "RSA", "kid", "k1", "use", "sig", "alg", "RS256",
                "n", Base64Url.encode(unsigned(pub.getModulus().toByteArray())), "e", Base64Url.encode(unsigned(pub.getPublicExponent().toByteArray()))))))).getBytes(StandardCharsets.UTF_8);
        server.createContext("/.well-known/jwks.json", ex -> {
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, jwks.length);
            ex.getResponseBody().write(jwks);
            ex.close();
        });
        server.start();
        try {
            String issuer = "http://127.0.0.1:" + server.getAddress().getPort();
            JwtDecoder decoder = TouchqueResourceServerConfiguration.jwtDecoder(issuer, "https://api.acme.test");
            long now = Instant.now().getEpochSecond();
            String good = jwt(key, "at+jwt", Map.of("iss", issuer, "sub", "usr_1", "aud", java.util.List.of("https://api.acme.test"), "exp", now + 300, "iat", now, "scope", "read:orders"));
            assertEquals("usr_1", decoder.decode(good).getSubject());
            assertThrows(JwtException.class, () -> decoder.decode(jwt(key, "JWT", Map.of("iss", issuer, "sub", "usr_1", "aud", "https://api.acme.test", "exp", now + 300))));
            assertThrows(JwtException.class, () -> decoder.decode(jwt(key, "at+jwt", Map.of("iss", issuer, "sub", "usr_1", "aud", "https://other.test", "exp", now + 300))));
            assertThrows(JwtException.class, () -> decoder.decode(jwt(key, "at+jwt", Map.of("iss", "https://evil.test", "sub", "usr_1", "aud", "https://api.acme.test", "exp", now + 300))));
        } finally {
            server.stop(0);
        }
    }

    private static byte[] unsigned(byte[] b) {
        return b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b;
    }

    private static String jwt(KeyPair key, String typ, Map<String, Object> claims) throws Exception {
        String input = Base64Url.encode(Json.write(Json.object().put("alg", "RS256").put("typ", typ).put("kid", "k1"))) + "." + Base64Url.encode(Json.write(Json.toNode(claims)));
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key.getPrivate());
        s.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + Base64Url.encode(s.sign());
    }
}
