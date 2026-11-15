package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import com.touchque.agents.CrossAppAccess;
import com.touchque.crypto.AgentKeys;
import com.touchque.crypto.Jws;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Json;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * DPoP proofs for an ID-JAG key (RFC 9449): their shape, the method (trimmed, uppercased, an HTTP
 * token), the access token hash and a server nonce, the htu rules; and the one nonce retry of
 * requestIdJag and redeemIdJag against a token endpoint on this machine (section 8): the same request
 * once more with a new proof carrying a valid nonce, never a second time, never without a key, and the
 * latest valid nonce on the error. A 64 KB WWW-Authenticate header takes well under a second.
 */
class IdJagDpopTest {
    private static final String NONCE_REFUSAL = "{\"error\":\"use_dpop_nonce\",\"error_description\":\"Authorization server requires nonce in DPoP proof\"}";

    private static List<String> names(JsonNode node) {
        List<String> out = new ArrayList<>();
        node.fieldNames().forEachRemaining(out::add);
        return out;
    }

    /** base64url (no padding) SHA-256 over the token's ASCII bytes, computed here, not by the SDK. */
    private static String ath(String token) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII)));
    }

    /** The proof's parts, after checking what every proof keeps: header, public jwk, signature, iat and jti. */
    private static Jws.Parts checked(String proof, CrossAppAccess.IdJagDpopKey key) {
        Jws.Parts p = Jws.split(proof);
        assertEquals(List.of("typ", "jwk", "alg"), names(p.header()));
        assertEquals(List.of("dpop+jwt", "ES256"), List.of(Json.str(p.header(), "typ"), Json.str(p.header(), "alg")));
        JsonNode jwk = p.header().get("jwk");
        assertEquals(List.of("kty", "crv", "x", "y"), names(jwk));
        assertEquals(List.of("EC", "P-256", 32, 32), List.of(Json.str(jwk, "kty"), Json.str(jwk, "crv"),
                Base64Url.decode(Json.str(jwk, "x")).length, Base64Url.decode(Json.str(jwk, "y")).length));
        assertEquals(key.thumbprint(), AgentKeys.thumbprint(jwk));
        assertEquals(64, p.signature().length);
        assertTrue(Jws.verify("ES256", jwk, p.input(), p.signature()));
        assertTrue(p.claims().get("iat").isIntegralNumber());
        assertTrue(Math.abs(p.claims().get("iat").asLong() - Instant.now().getEpochSecond()) <= 5);
        assertTrue(Json.str(p.claims(), "jti").matches("[0-9a-f]{32}"));
        return p;
    }

    private static String htu(String url) {
        return Json.str(Jws.split(CrossAppAccess.idJagDpopProof(CrossAppAccess.createIdJagDpopKey(), url)).claims(), "htu");
    }

    @Test
    void proofOptions() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        String url = "https://sso.touchque.com/sso/token?x=1#f";
        Set<String> jtis = new HashSet<>();

        // The token-endpoint form: POST, no ath, no nonce; the same as the long form with nulls.
        for (String proof : List.of(CrossAppAccess.idJagDpopProof(key, url), CrossAppAccess.idJagDpopProof(key, null, url, null, null),
                CrossAppAccess.idJagDpopProof(key, "", url, "", ""))) {
            Jws.Parts p = checked(proof, key);
            assertEquals(List.of("htm", "htu", "iat", "jti"), names(p.claims()));
            assertEquals(List.of("POST", "https://sso.touchque.com/sso/token"), List.of(Json.str(p.claims(), "htm"), Json.str(p.claims(), "htu")));
            jtis.add(Json.str(p.claims(), "jti"));
        }

        // A resource request with a DPoP-bound access token: its method (uppercased) and ath.
        String token = "eyJhbGciOiJFUzI1NiJ9.e30.Kz-8_qY~+/=";
        Jws.Parts get = checked(CrossAppAccess.idJagDpopProof(key, "get", "https://API.Example.com:443/v1/files?x=1", token, null), key);
        assertEquals(List.of("htm", "htu", "iat", "jti", "ath"), names(get.claims()));
        assertEquals(List.of("GET", "https://api.example.com/v1/files", ath(token)),
                List.of(Json.str(get.claims(), "htm"), Json.str(get.claims(), "htu"), Json.str(get.claims(), "ath")));
        jtis.add(Json.str(get.claims(), "jti"));

        // A server's nonce, alone and with an access token.
        Jws.Parts nonce = checked(CrossAppAccess.idJagDpopProof(key, null, url, null, "n-1"), key);
        assertEquals(List.of("htm", "htu", "iat", "jti", "nonce"), names(nonce.claims()));
        assertEquals(List.of("POST", "n-1"), List.of(Json.str(nonce.claims(), "htm"), Json.str(nonce.claims(), "nonce")));
        jtis.add(Json.str(nonce.claims(), "jti"));
        Jws.Parts both = checked(CrossAppAccess.idJagDpopProof(key, "Delete", "https://api.example.com/v1/files/7", "at", "n-2"), key);
        assertEquals(List.of("DELETE", ath("at"), "n-2"), List.of(Json.str(both.claims(), "htm"), Json.str(both.claims(), "ath"), Json.str(both.claims(), "nonce")));
        jtis.add(Json.str(both.claims(), "jti"));

        assertEquals(6, jtis.size());   // a fresh jti every time
        assertTrue(CrossAppAccess.idJagDpopProof(key, url).split("\\.")[2].matches("[A-Za-z0-9_-]{86}"));   // 64 bytes, base64url, no padding
    }

    @Test
    void htuRules() {
        // Scheme and host lowercased, default port dropped, "/" for an empty path, the path as given (dot segments and
        // percent-encoding too; raw non-ASCII percent-encoded as the JDK's HttpClient sends it), no user info, query or fragment.
        Map<String, String> cases = Map.ofEntries(
                Map.entry("https://API.Example.com:443/v1/files?x=1", "https://api.example.com/v1/files"),
                Map.entry("HTTPS://Example.COM", "https://example.com/"),
                Map.entry("https://x.example#frag", "https://x.example/"),
                Map.entry("https://x.example?q=1", "https://x.example/"),
                Map.entry("http://Sso.Example:8080/token", "http://sso.example:8080/token"),
                Map.entry("http://example.com:80/x", "http://example.com/x"),
                Map.entry("http://example.com:443/x", "http://example.com:443/x"),
                Map.entry("https://example.com:80/x", "https://example.com:80/x"),
                Map.entry("https://x.example:0443/p", "https://x.example/p"),
                Map.entry("http://127.0.0.1:8080", "http://127.0.0.1:8080/"),
                Map.entry("http://[::1]:80/x", "http://[::1]/x"),
                Map.entry("https://[2001:DB8::1]:443/x", "https://[2001:db8::1]/x"),
                Map.entry("https://user:pw@Host.example:8443/a/../b/./c?q#f", "https://host.example:8443/a/../b/./c"),
                Map.entry("https://x.example/./a/.%2E/b/%2e", "https://x.example/./a/.%2E/b/%2e"),
                Map.entry("https://x.example/a/b/..", "https://x.example/a/b/.."),
                Map.entry("https://x.example/%2e%2e%2e/x", "https://x.example/%2e%2e%2e/x"),
                Map.entry("https://x.example/a%2Fb/%7euser/%7E", "https://x.example/a%2Fb/%7euser/%7E"),
                Map.entry("https://x.example/a//b/", "https://x.example/a//b/"),
                Map.entry("https://x.example/\u00fc/%c3%bc", "https://x.example/%C3%BC/%c3%bc"),
                Map.entry("https://x.example/u\u0308", "https://x.example/%C3%BC"),
                Map.entry("https://x.example/A/B", "https://x.example/A/B"),
                Map.entry("https://x.example/a;b=c/d@e:f+g$h,i!j*k'l(m)n&o=p", "https://x.example/a;b=c/d@e:f+g$h,i!j*k'l(m)n&o=p"));
        cases.forEach((url, expected) -> assertEquals(expected, htu(url), url));
        // Not an absolute http(s) URL the JDK's HttpClient could call.
        for (String bad : List.of("/token", "token", "ftp://x.example/a", "https:example.com", "https://x.example/a b", "https://x.example:65536/")) {
            assertThrows(TouchqueConfigException.class, () -> htu(bad), bad);
        }
    }

    @Test
    void htmIsTheMethodTrimmedAndUppercased() {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        String url = "https://api.example.com/v1/files";
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put(null, "POST");
        cases.put("", "POST");
        cases.put(" \t\r\n", "POST");
        cases.put(" get ", "GET");
        cases.put("\tPatch\n", "PATCH");
        cases.put("m-search", "M-SEARCH");
        cases.put("x!#$%&'*+-.^_`|~09", "X!#$%&'*+-.^_`|~09");
        cases.forEach((method, htm) -> assertEquals(htm, Json.str(checked(CrossAppAccess.idJagDpopProof(key, method, url, null, null), key).claims(), "htm"),
                String.valueOf(method)));
        // Anything but RFC 9110 token characters: a configuration error, never a proof.
        for (String bad : List.of("GE T", "GET\u0000", "\u0000GET", "G\u00c9T", "g\u0131t", "get(1)", "\"GET\"", "GET,POST", "GET/1", "\u00a0GET", "GET\\")) {
            assertThrows(TouchqueConfigException.class, () -> CrossAppAccess.idJagDpopProof(key, bad, url, null, null), bad);
        }
    }

    /** What the token endpoint received: the DPoP header as sent, Authorization and the form body. */
    record Received(String dpop, String authorization, String body) {
        Jws.Parts proof() {
            return dpop == null ? null : Jws.split(dpop);
        }
    }

    /** One answer: status (0: none, the connection is closed), JSON body (empty: none) and headers. */
    record Reply(int status, String json, Map<String, List<String>> headers) {
        static Reply of(int status, String json, String... headers) {
            Map<String, List<String>> map = new LinkedHashMap<>();
            for (int i = 0; i < headers.length; i += 2) map.computeIfAbsent(headers[i], k -> new ArrayList<>()).add(headers[i + 1]);
            return new Reply(status, json, map);
        }
    }

    /** A token endpoint on this machine: answers with {@code reply} and keeps what it received. */
    private static final class TokenEndpoint implements AutoCloseable {
        final List<Received> received = new CopyOnWriteArrayList<>();
        final String url;
        private final HttpServer server;

        TokenEndpoint(Function<List<Received>, Reply> reply) throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", ex -> {
                received.add(new Received(ex.getRequestHeaders().getFirst("DPoP"), ex.getRequestHeaders().getFirst("Authorization"),
                        new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
                Reply out = reply.apply(received);
                if (out.status() == 0) {
                    ex.close();   // nothing sent: the client's request fails with an IOException
                    return;
                }
                byte[] bytes = out.json().getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().add("Content-Type", "application/json");
                out.headers().forEach((name, values) -> values.forEach(v -> ex.getResponseHeaders().add(name, v)));
                ex.sendResponseHeaders(out.status(), bytes.length == 0 ? -1 : bytes.length);
                if (bytes.length > 0) ex.getResponseBody().write(bytes);
                ex.close();
            });
            server.start();
            url = "http://127.0.0.1:" + server.getAddress().getPort() + "/token";
        }

        Received last() {
            return received.get(received.size() - 1);
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    private static String nonceOf(Received r) {
        return r.proof() == null ? null : Json.str(r.proof().claims(), "nonce");
    }

    /** An ID-JAG bound to the proof's key, as an identity provider that does DPoP answers. */
    private static Reply boundIdJag(Received r) {
        ObjectNode claims = Json.object();
        claims.set("cnf", Json.object().put("jkt", AgentKeys.thumbprint(r.proof().header().get("jwk"))));
        String jag = Base64Url.encode("{\"typ\":\"oauth-id-jag+jwt\",\"alg\":\"RS256\"}") + "." + Base64Url.encode(Json.write(claims)) + ".sig";
        return Reply.of(200, Json.write(Json.object().put("access_token", jag).put("issued_token_type", CrossAppAccess.ID_JAG_TOKEN_TYPE).put("token_type", "N_A")));
    }

    private static void assertSameRequestWithTheNonce(TokenEndpoint ep, CrossAppAccess.IdJagDpopKey key, String nonce) {
        assertEquals(2, ep.received.size());
        Received first = ep.received.get(0);
        Received second = ep.received.get(1);
        Jws.Parts a = checked(first.dpop(), key);
        Jws.Parts b = checked(second.dpop(), key);
        assertNull(nonceOf(first));
        assertEquals(nonce, nonceOf(second));
        assertNotEquals(Json.str(a.claims(), "jti"), Json.str(b.claims(), "jti"));
        assertEquals(List.of("POST", ep.url), List.of(Json.str(b.claims(), "htm"), Json.str(b.claims(), "htu")));
        assertEquals(Json.str(a.claims(), "htu"), Json.str(b.claims(), "htu"));
        assertEquals(first.body(), second.body());
        assertEquals(first.authorization(), second.authorization());
    }

    @Test
    void requestIdJagRetriesOnceWithTheServersNonce() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        try (TokenEndpoint ep = new TokenEndpoint(seen -> "n-1".equals(nonceOf(seen.get(seen.size() - 1))) ? boundIdJag(seen.get(seen.size() - 1))
                : Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", "n-1"))) {
            CrossAppAccess.IdJagGrant jag = CrossAppAccess.requestIdJag(new CrossAppAccess.RequestOptions("tqapp_test", "tqs_test", "idtoken:ada", "https://rs.example")
                    .tokenEndpoint(ep.url + "?x=1").dpopKey(key));
            assertEquals(Boolean.TRUE, jag.dpopBound());
            assertSameRequestWithTheNonce(ep, key, "n-1");
            assertEquals("Basic " + Base64.getEncoder().encodeToString("tqapp_test:tqs_test".getBytes(StandardCharsets.UTF_8)), ep.last().authorization());
            assertTrue(ep.last().body().contains("subject_token=idtoken%3Aada"), ep.last().body());
        }
    }

    @Test
    void redeemIdJagRetriesOnceOnA401DpopChallenge() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        // 401 with the nonce asked for in WWW-Authenticate only (RFC 9449 section 9 style), among other challenges.
        try (TokenEndpoint ep = new TokenEndpoint(seen -> "n-1".equals(nonceOf(seen.get(seen.size() - 1)))
                ? Reply.of(200, "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}")
                : Reply.of(401, "", "WWW-Authenticate", "Bearer realm=\"files, DPoP\", DPoP algs=\"ES256 PS256\", error=\"use_dpop_nonce\", "
                        + "error_description=\"Authorization server requires nonce in DPoP proof\"", "DPoP-Nonce", "n-1"))) {
            JsonNode tokens = CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret").dpopKey(key));
            assertEquals("DPoP", Json.str(tokens, "token_type"));
            assertSameRequestWithTheNonce(ep, key, "n-1");
            assertEquals("Basic " + Base64.getEncoder().encodeToString("acme-at-rs:rs_secret".getBytes(StandardCharsets.UTF_8)), ep.last().authorization());
        }
        // A public client: client_id in the form, both times; the challenge in its own header, lowercase scheme, token value.
        try (TokenEndpoint ep = new TokenEndpoint(seen -> "n-7".equals(nonceOf(seen.get(seen.size() - 1)))
                ? Reply.of(200, "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}")
                : Reply.of(401, "{}", "WWW-Authenticate", "Bearer realm=\"files\"", "WWW-Authenticate", "dpop error=use_dpop_nonce", "DPoP-Nonce", "n-7"))) {
            CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").dpopKey(key));
            assertSameRequestWithTheNonce(ep, key, "n-7");
            assertNull(ep.last().authorization());
            assertTrue(ep.last().body().contains("client_id=acme-at-rs"), ep.last().body());
        }
        // A challenge with a token68 (padded) first, then the DPoP one with spaces around "=".
        try (TokenEndpoint ep = new TokenEndpoint(seen -> "n-8".equals(nonceOf(seen.get(seen.size() - 1)))
                ? Reply.of(200, "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}")
                : Reply.of(401, "", "WWW-Authenticate", "Negotiate a87421000492aa874209af8bc028==, DPoP error = \"use_dpop_nonce\"", "DPoP-Nonce", "n-8"))) {
            CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret").dpopKey(key));
            assertSameRequestWithTheNonce(ep, key, "n-8");
        }
    }

    @Test
    void neverASecondRetryAndTheErrorCarriesTheLatestNonce() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        try (TokenEndpoint ep = new TokenEndpoint(seen -> Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", "n-" + seen.size()))) {
            TouchqueIdJagException e = assertThrows(TouchqueIdJagException.class,
                    () -> CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret").dpopKey(key)));
            assertEquals(List.of("use_dpop_nonce", 400, "n-2"), List.of(e.error(), e.status(), e.dpopNonce()));
            assertEquals("Authorization server requires nonce in DPoP proof", e.getMessage());
            assertSameRequestWithTheNonce(ep, key, "n-1");
        }
    }

    @Test
    void theErrorCarriesTheLatestValidNonceTheServerSent() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        Reply first = Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", "n-1");
        record Case(Reply retry, String error, Integer status, String nonce) {
        }
        List<Case> cases = List.of(
                // The retry's answer has a nonce: that one.
                new Case(Reply.of(400, "{\"error\":\"invalid_dpop_proof\"}", "DPoP-Nonce", "n-2"), "invalid_dpop_proof", 400, "n-2"),
                // No nonce, an invalid one or two different ones on the retry's answer: the first answer's.
                new Case(Reply.of(400, "{\"error\":\"invalid_grant\"}"), "invalid_grant", 400, "n-1"),
                new Case(Reply.of(400, "{\"error\":\"invalid_grant\"}", "DPoP-Nonce", "n 2"), "invalid_grant", 400, "n-1"),
                new Case(Reply.of(401, "", "DPoP-Nonce", "n-2", "DPoP-Nonce", "n-3"), "server_error", 401, "n-1"),
                // No answer to the retry: still the first answer's.
                new Case(new Reply(0, "", Map.of()), "temporarily_unavailable", null, "n-1"));
        for (Case c : cases) {
            try (TokenEndpoint ep = new TokenEndpoint(seen -> seen.size() == 1 ? first : c.retry())) {
                TouchqueIdJagException e = assertThrows(TouchqueIdJagException.class,
                        () -> CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret").dpopKey(key)));
                assertEquals(Arrays.asList(c.error(), c.status(), c.nonce()), Arrays.asList(e.error(), e.status(), e.dpopNonce()), c.toString());
                assertSameRequestWithTheNonce(ep, key, "n-1");
            }
        }
        // An identity provider that answers the retry without an ID-JAG: invalid_response, with the latest nonce too.
        String notAnIdJag = "{\"access_token\":\"at\",\"token_type\":\"Bearer\"}";
        for (Reply retry : List.of(Reply.of(200, notAnIdJag, "DPoP-Nonce", "n-2"), Reply.of(200, notAnIdJag))) {
            try (TokenEndpoint ep = new TokenEndpoint(seen -> seen.size() == 1 ? first : retry)) {
                TouchqueIdJagException e = assertThrows(TouchqueIdJagException.class, () -> CrossAppAccess.requestIdJag(
                        new CrossAppAccess.RequestOptions("tqapp_test", "tqs_test", "idtoken:ada", "https://rs.example").tokenEndpoint(ep.url).dpopKey(key)));
                assertEquals(List.of("invalid_response", retry.headers().isEmpty() ? "n-1" : "n-2"), List.of(e.error(), e.dpopNonce()));
                assertSameRequestWithTheNonce(ep, key, "n-1");
            }
        }
    }

    @Test
    void aRepeatedNonceAndEveryNqcharAreRetried() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        // 1*NQCHAR: %x21 / %x23-5B / %x5D-7E, every one of them here; the same value twice counts once.
        StringBuilder all = new StringBuilder();
        for (char c = 0x21; c <= 0x7e; c++) if (c != '"' && c != '\\') all.append(c);
        for (List<String> nonces : List.of(List.of(all.toString()), List.of("n-1", "n-1"))) {
            List<String> headers = new ArrayList<>();
            nonces.forEach(n -> headers.addAll(List.of("DPoP-Nonce", n)));
            Reply refusal = Reply.of(400, NONCE_REFUSAL, headers.toArray(String[]::new));
            String nonce = nonces.get(0);
            try (TokenEndpoint ep = new TokenEndpoint(seen -> nonce.equals(nonceOf(seen.get(seen.size() - 1)))
                    ? Reply.of(200, "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}") : refusal)) {
                CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret").dpopKey(key));
                assertSameRequestWithTheNonce(ep, key, nonce);
            }
        }
    }

    @Test
    void noRetryWithoutAKey() throws Exception {
        try (TokenEndpoint ep = new TokenEndpoint(seen -> Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", "n-1"))) {
            TouchqueIdJagException e = assertThrows(TouchqueIdJagException.class, () -> CrossAppAccess.requestIdJag(
                    new CrossAppAccess.RequestOptions("tqapp_test", "tqs_test", "idtoken:ada", "https://rs.example").tokenEndpoint(ep.url)));
            assertEquals(List.of("use_dpop_nonce", 400, "n-1"), List.of(e.error(), e.status(), e.dpopNonce()));
            TouchqueIdJagException r = assertThrows(TouchqueIdJagException.class,
                    () -> CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag")));
            assertEquals(List.of("use_dpop_nonce", 400, "n-1"), List.of(r.error(), r.status(), r.dpopNonce()));
            assertEquals(2, ep.received.size());   // one request each, no DPoP header
            assertTrue(ep.received.stream().allMatch(x -> x.proof() == null));
        }
    }

    /** Runs {@code call} on a thread with a 256 KB stack; what it threw, or null. */
    private static Throwable onASmallStack(Executable call) throws InterruptedException {
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        Thread t = new Thread(null, () -> {
            try {
                call.execute();
            } catch (Throwable e) {
                thrown.set(e);
            }
        }, "small-stack", 256 * 1024);
        t.start();
        t.join();
        return thrown.get();
    }

    @Test
    void aLongWwwAuthenticateHeaderCostsNoStack() throws Exception {
        // One quoted-string of 72,000 characters, with escaped quotes and commas inside.
        String quoted = "\"" + "a\\\", b".repeat(12_000) + "\"";
        // No key: the header is never read. A 200 returns as before, a 401 throws the usual error; one request each.
        try (TokenEndpoint ep = new TokenEndpoint(seen -> seen.size() == 1
                ? Reply.of(200, "{\"access_token\":\"at\",\"token_type\":\"Bearer\"}", "WWW-Authenticate", "Bearer realm=" + quoted)
                : Reply.of(401, NONCE_REFUSAL, "WWW-Authenticate", "DPoP x=" + quoted + ", error=\"use_dpop_nonce\"", "DPoP-Nonce", "n-1"))) {
            AtomicReference<JsonNode> tokens = new AtomicReference<>();
            assertNull(onASmallStack(() -> tokens.set(CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret")))));
            assertEquals("at", Json.str(tokens.get(), "access_token"));
            TouchqueIdJagException e = assertInstanceOf(TouchqueIdJagException.class,
                    onASmallStack(() -> CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret"))));
            assertEquals(List.of("use_dpop_nonce", 401, "n-1"), List.of(e.error(), e.status(), e.dpopNonce()));
            assertEquals(2, ep.received.size());
            assertTrue(ep.received.stream().allMatch(x -> x.proof() == null));
        }
        // With a key: a 401 asking for the nonce in WWW-Authenticate only, after the long param. The same request once more.
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        try (TokenEndpoint ep = new TokenEndpoint(seen -> "n-1".equals(nonceOf(seen.get(seen.size() - 1)))
                ? Reply.of(200, "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}")
                : Reply.of(401, "", "WWW-Authenticate", "DPoP x=" + quoted + ", error=\"use_dpop_nonce\"", "DPoP-Nonce", "n-1"))) {
            assertNull(onASmallStack(() -> CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret").dpopKey(key))));
            assertSameRequestWithTheNonce(ep, key, "n-1");
        }
        // The same error only inside the long quoted value: no retry.
        try (TokenEndpoint ep = new TokenEndpoint(seen -> Reply.of(401, "", "WWW-Authenticate",
                "DPoP x=\"" + "a, error=\\\"use_dpop_nonce\\\"".repeat(3_000) + "\"", "DPoP-Nonce", "n-1"))) {
            TouchqueIdJagException e = assertInstanceOf(TouchqueIdJagException.class,
                    onASmallStack(() -> CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").dpopKey(key))));
            assertEquals(List.of("server_error", 401, "n-1"), List.of(e.error(), e.status(), e.dpopNonce()));
            assertEquals(1, ep.received.size());
        }
    }

    /** What {@code call} threw (or null) on a 256 KB stack, and how long it took. */
    private record Run(Throwable thrown, long millis) {
        static Run of(Executable call) throws InterruptedException {
            long start = System.nanoTime();
            Throwable thrown = onASmallStack(call);
            return new Run(thrown, (System.nanoTime() - start) / 1_000_000);
        }
    }

    @Test
    void a64KbWwwAuthenticateOrDpopNonceHeaderTakesWellUnderASecond() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        String bearer = "{\"access_token\":\"at\",\"token_type\":\"Bearer\"}";
        String dpop = "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}";
        // One call first, so the times below are the header's and not the first connection's.
        try (TokenEndpoint ep = new TokenEndpoint(seen -> Reply.of(200, bearer))) {
            CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret").dpopKey(key));
        }
        // A 65,536-character quoted param, and 30,000 list elements.
        for (String header : List.of("DPoP realm=\"" + "a".repeat(65_536) + "\"", "DPoP " + "a,".repeat(30_000))) {
            String what = header.substring(0, 14) + "... (" + header.length() + " characters)";
            // A 200 without a key: the tokens, as always.
            try (TokenEndpoint ep = new TokenEndpoint(seen -> Reply.of(200, bearer, "WWW-Authenticate", header))) {
                AtomicReference<JsonNode> tokens = new AtomicReference<>();
                Run run = Run.of(() -> tokens.set(CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret"))));
                assertNull(run.thrown(), what);
                assertEquals("at", Json.str(tokens.get(), "access_token"), what);
                assertTrue(run.millis() < 1000, what + ": " + run.millis() + " ms");
            }
            // A 401 with a key and a nonce: the whole header is read and asks for no nonce, so the usual error, no retry.
            try (TokenEndpoint ep = new TokenEndpoint(seen -> Reply.of(401, "", "WWW-Authenticate", header, "DPoP-Nonce", "n-1"))) {
                Run run = Run.of(() -> CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret").dpopKey(key)));
                TouchqueIdJagException e = assertInstanceOf(TouchqueIdJagException.class, run.thrown(), what);
                assertEquals(List.of("server_error", 401, "n-1", 1), List.of(e.error(), e.status(), e.dpopNonce(), ep.received.size()), what);
                assertTrue(run.millis() < 1000, what + ": " + run.millis() + " ms");
            }
            // The same header with a DPoP use_dpop_nonce challenge after it: found at the end, one retry with the nonce.
            try (TokenEndpoint ep = new TokenEndpoint(seen -> "n-1".equals(nonceOf(seen.get(seen.size() - 1))) ? Reply.of(200, dpop)
                    : Reply.of(401, "", "WWW-Authenticate", header + ", DPoP error=\"use_dpop_nonce\"", "DPoP-Nonce", "n-1"))) {
                Run run = Run.of(() -> CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret").dpopKey(key)));
                assertNull(run.thrown(), what);
                assertSameRequestWithTheNonce(ep, key, "n-1");
                assertTrue(run.millis() < 1000, what + ": " + run.millis() + " ms");
            }
        }
        // A 65,536-character DPoP-Nonce in valid syntax: the retry carries all of it (a DPoP header of about 87 KB).
        String big = "n".repeat(65_536);
        try (TokenEndpoint ep = new TokenEndpoint(seen -> big.equals(nonceOf(seen.get(seen.size() - 1))) ? Reply.of(200, dpop)
                : Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", big))) {
            Run run = Run.of(() -> CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret").dpopKey(key)));
            assertNull(run.thrown());
            assertSameRequestWithTheNonce(ep, key, big);
            assertTrue(run.millis() < 1000, "64 KB nonce: " + run.millis() + " ms");
        }
    }

    @Test
    void retriesOnlyWhenTheServerAsksForItsNonce() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        String challenge = "DPoP error=\"use_dpop_nonce\"";
        record Case(Reply reply, String error, Integer status, String nonce) {
        }
        List<Case> cases = List.of(
                // use_dpop_nonce without a DPoP-Nonce header: nothing to retry with.
                new Case(Reply.of(400, NONCE_REFUSAL), "use_dpop_nonce", 400, null),
                // Another error: its nonce is still handed over.
                new Case(Reply.of(400, "{\"error\":\"invalid_grant\"}", "DPoP-Nonce", "n-1"), "invalid_grant", 400, "n-1"),
                new Case(Reply.of(403, NONCE_REFUSAL, "DPoP-Nonce", "n-1"), "use_dpop_nonce", 403, "n-1"),
                // The header counts for a 401 only, and only in a DPoP challenge.
                new Case(Reply.of(400, "", "WWW-Authenticate", challenge, "DPoP-Nonce", "n-1"), "server_error", 400, "n-1"),
                new Case(Reply.of(401, "", "WWW-Authenticate", "Bearer error=\"use_dpop_nonce\"", "DPoP-Nonce", "n-1"), "server_error", 401, "n-1"),
                new Case(Reply.of(401, "", "WWW-Authenticate", "Bearer realm=\"DPoP error=use_dpop_nonce\"", "DPoP-Nonce", "n-1"), "server_error", 401, "n-1"),
                new Case(Reply.of(401, "", "WWW-Authenticate", "DPoP error=\"use_dpop_nonce", "DPoP-Nonce", "n-1"), "server_error", 401, "n-1"),
                new Case(Reply.of(401, "", "WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\"", "DPoP-Nonce", "n-1"), "server_error", 401, "n-1"),
                // A DPoP-Nonce that is empty, not 1*NQCHAR (space, '"', '\', non-ASCII) or repeated with different values:
                // no retry, and the error never carries it.
                new Case(Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", ""), "use_dpop_nonce", 400, null),
                new Case(Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", "n 1"), "use_dpop_nonce", 400, null),
                new Case(Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", "n\"1"), "use_dpop_nonce", 400, null),
                new Case(Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", "n\\1"), "use_dpop_nonce", 400, null),
                new Case(Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", "n\u00fc"), "use_dpop_nonce", 400, null),
                new Case(Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", "n-1", "DPoP-Nonce", "n-2"), "use_dpop_nonce", 400, null),
                new Case(Reply.of(401, "", "WWW-Authenticate", challenge, "DPoP-Nonce", "n-1, n-2"), "server_error", 401, null),
                new Case(Reply.of(401, "", "WWW-Authenticate", challenge, "DPoP-Nonce", "n".repeat(65_535) + "\u00ff"), "server_error", 401, null),
                // A control character in the header: the HTTP client refuses the answer, still an ID-JAG error.
                new Case(Reply.of(400, NONCE_REFUSAL, "DPoP-Nonce", "n\u007f1"), "temporarily_unavailable", null, null));
        for (Case c : cases) {
            try (TokenEndpoint ep = new TokenEndpoint(seen -> c.reply())) {
                TouchqueIdJagException e = assertThrows(TouchqueIdJagException.class,
                        () -> CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(ep.url, "acme-at-rs", "the.id.jag").dpopKey(key)));
                assertEquals(Arrays.asList(1, c.error(), c.status()), Arrays.asList(ep.received.size(), e.error(), e.status()), c::toString);
                assertEquals(c.nonce(), e.dpopNonce(), c::toString);
            }
        }
    }
}
