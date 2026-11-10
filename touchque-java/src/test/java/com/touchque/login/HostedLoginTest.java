package com.touchque.login;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.Support;
import com.touchque.TouchQueConfigException;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** TouchQue Login against an in-process fake tenant: JWKS, /oauth/token with PKCE, /bc-authorize, My Account; and the sealed cookies. */
class HostedLoginTest {
    static final String CLIENT_ID = "client-123";

    /** A fake TouchQue Login tenant on a local port (its issuer is that address). */
    static final class FakeTenant implements AutoCloseable {
        final KeyPair key = rsa();
        final Map<String, String[]> codes = new HashMap<>();
        final List<Support.Seen> posts = new ArrayList<>();
        KeyPair signWith;
        String nonceOverride;
        int polls;
        final Support.Stub stub;
        final String issuer;

        FakeTenant() throws Exception {
            stub = new Support.Stub(this::answer);
            issuer = stub.baseUrl;
        }

        static KeyPair rsa() {
            try {
                KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
                g.initialize(2048);
                return g.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        String jwt(ObjectNode payload, String typ, KeyPair with) {
            try {
                String input = Base64Url.encode(Json.write(Json.object().put("alg", "RS256").put("typ", typ).put("kid", "k1"))) + "." + Base64Url.encode(Json.write(payload));
                Signature s = Signature.getInstance("SHA256withRSA");
                s.initSign((with != null ? with : key).getPrivate());
                s.update(input.getBytes(StandardCharsets.US_ASCII));
                return input + "." + Base64Url.encode(s.sign());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        String[] authorize(String url) {
            Map<String, String> q = HostedLogin.parseQuery(url);
            String code = "code-" + codes.size();
            codes.put(code, new String[] {q.get("code_challenge"), q.get("nonce")});
            return new String[] {code, q.get("state")};
        }

        private static byte[] unsigned(java.math.BigInteger n) {
            byte[] b = n.toByteArray();
            return b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b;
        }

        private synchronized Support.Answer answer(Support.Seen req) {
            String path = req.path().split("\\?")[0];
            if (path.equals("/.well-known/jwks.json")) {
                RSAPublicKey pub = (RSAPublicKey) key.getPublic();
                return Support.Answer.json(200, Map.of("keys", List.of(Map.of("kty", "RSA", "kid", "k1", "use", "sig",
                        "n", Base64Url.encode(unsigned(pub.getModulus())), "e", Base64Url.encode(unsigned(pub.getPublicExponent()))))));
            }
            Map<String, String> f = HostedLogin.parseQuery(req.body());
            if (req.method().equals("POST")) posts.add(req);
            long now = Instant.now().getEpochSecond();
            if (path.equals("/bc-authorize")) return Support.Answer.json(200, Map.of("auth_req_id", "req-1", "expires_in", 300, "interval", 0, "binding_code", "42"));
            if (path.equals("/me/v1/profile") && req.method().equals("PATCH")) return Support.Answer.json(200, Json.object().set("profile", Json.parse(req.body())));
            if (path.equals("/me/v1/password")) return Support.Answer.json(401, Map.of("error", "insufficient_user_authentication", "error_description", "Sign in again", "max_age", 0));
            if (path.equals("/me/v1/sessions/s1")) return new Support.Answer(204, null, Map.of());
            if (!path.equals("/oauth/token")) return Support.Answer.json(404, Map.of());
            String grant = f.getOrDefault("grant_type", "");
            switch (grant) {
                case "authorization_code" -> {
                    String[] c = codes.get(f.get("code"));
                    if (c == null || !c[0].equals(Base64Url.encode(Crypto.sha256(f.get("code_verifier").getBytes(StandardCharsets.US_ASCII))))) {
                        return Support.Answer.json(400, Map.of("error", "invalid_grant"));
                    }
                    ObjectNode atClaims = Json.object().put("iss", issuer).put("sub", "usr_1").put("exp", now + 300).put("iat", now).put("client_id", CLIENT_ID)
                            .put("scope", "openid read:orders");
                    atClaims.set("aud", Json.array().add("https://api.acme.test"));
                    String at = jwt(atClaims, "at+jwt", null);
                    String id = jwt(Json.object().put("iss", issuer).put("sub", "usr_1").put("aud", CLIENT_ID).put("exp", now + 300).put("iat", now)
                            .put("nonce", nonceOverride != null ? nonceOverride : c[1]).put("email", "a@acme.test")
                            .put("at_hash", Base64Url.encode(Arrays.copyOf(Crypto.sha256(at.getBytes(StandardCharsets.US_ASCII)), 16))), "JWT", signWith);
                    return Support.Answer.json(200, Map.of("access_token", at, "token_type", "Bearer", "expires_in", 300, "scope", "openid", "id_token", id, "refresh_token", "tqr_1"));
                }
                case "refresh_token" -> {
                    return Support.Answer.json(200, Map.of("access_token", "x", "token_type", "Bearer", "expires_in", 300, "refresh_token", "tqr_2"));
                }
                case "urn:ietf:params:oauth:grant-type:token-exchange" -> {
                    if (HostedLogin.CONNECTION_TOKEN_TYPE.equals(f.get("requested_token_type"))) {
                        return Support.Answer.json(200, Map.of("access_token", "ya29.g", "token_type", "Bearer", "expires_in", 3500, "scope", "openid email", "connection", f.get("connection")));
                    }
                    return Support.Answer.json(200, Map.of("access_token", "at-x", "token_type", "Bearer", "expires_in", 120, "issued_token_type", "urn:ietf:params:oauth:token-type:access_token"));
                }
                case "urn:openid:params:grant-type:ciba" -> {
                    polls++;
                    if (polls == 1) return Support.Answer.json(400, Map.of("error", "authorization_pending"));
                    if ("denied".equals(f.get("auth_req_id"))) return Support.Answer.json(400, Map.of("error", "access_denied"));
                    return Support.Answer.json(200, Map.of("access_token", "at-c", "token_type", "Bearer", "expires_in", 300,
                            "authorization_details", List.of(Map.of("type", "payment_initiation"))));
                }
                default -> {
                    return Support.Answer.json(400, Map.of("error", "unsupported_grant_type"));
                }
            }
        }

        @Override
        public void close() {
            stub.close();
        }
    }

    private final FakeTenant tenant = newTenant();

    private static FakeTenant newTenant() {
        try {
            return new FakeTenant();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @AfterEach
    void stop() {
        tenant.close();
    }

    private HostedLogin login(String secret) {
        return new HostedLogin(new HostedLogin.Options(tenant.issuer, CLIENT_ID).clientSecret(secret).redirectUri("https://app/cb"));
    }

    @Test
    void authorizationUrl() {
        HostedLogin.AuthorizationRequest req = new HostedLogin(new HostedLogin.Options("acme.login.touchque.com", CLIENT_ID).redirectUri("https://app/cb").audience("https://api.acme.test"))
                .authorizationUrl(new HostedLogin.AuthorizationOptions().screenHint("signup"));
        Map<String, String> q = HostedLogin.parseQuery(req.url());
        assertTrue(req.url().startsWith("https://acme.login.touchque.com/authorize?"));
        assertEquals(Base64Url.encode(Crypto.sha256(req.codeVerifier().getBytes(StandardCharsets.US_ASCII))), q.get("code_challenge"));
        assertEquals(List.of("S256", req.state(), "signup", "https://api.acme.test"), List.of(q.get("code_challenge_method"), q.get("state"), q.get("screen_hint"), q.get("audience")));
    }

    @Test
    void plaintextHttpDomainsOnlyOnThisMachine() {
        for (String domain : List.of("http://acme.login.touchque.com", "HTTP://acme.login.touchque.com/", "http://localhost.evil.example", "http://localhost@evil.example")) {
            assertEquals("config", assertThrows(HostedLoginException.class, () -> new HostedLogin(new HostedLogin.Options(domain, CLIENT_ID))).errorCode(), domain);
        }
        assertThrows(HostedLoginException.class, () -> new MyAccount("http://acme.login.touchque.com", "at"));
        for (String domain : List.of("http://localhost:5001", "http://127.0.0.1:5001", "http://[::1]:5001", "https://acme.login.touchque.com")) {
            assertEquals(domain, new HostedLogin(new HostedLogin.Options(domain + "/", CLIENT_ID)).issuer());
        }
        assertEquals("http://shop.login.localhost:5001", HostedLogin.issuerOf("http://shop.login.localhost:5001/"));
        assertEquals("https://acme.login.touchque.com", HostedLogin.issuerOf("acme.login.touchque.com"));
    }

    @Test
    void callbackRefreshAndAccessToken() {
        HostedLogin login = login("s3cret");
        HostedLogin.AuthorizationRequest req = login.authorizationUrl(null);
        String[] a = tenant.authorize(req.url());
        HostedLogin.TokenSet tokens = login.handleCallback("https://app/cb?code=" + a[0] + "&state=" + java.net.URLEncoder.encode(a[1], StandardCharsets.UTF_8)
                + "&iss=" + java.net.URLEncoder.encode(tenant.issuer, StandardCharsets.UTF_8), new HostedLogin.CallbackChecks(req.state(), req.nonce(), req.codeVerifier()));
        assertEquals(List.of("usr_1", "tqr_1"), List.of(tokens.claims().get("sub").asText(), tokens.refreshToken()));
        assertEquals("Basic " + Base64.getEncoder().encodeToString((CLIENT_ID + ":s3cret").getBytes(StandardCharsets.UTF_8)), tenant.posts.get(0).header("Authorization"));
        assertEquals("tqr_2", login.refresh("tqr_1", null).refreshToken());
        assertEquals("usr_1", login.verifyAccessToken(tokens.accessToken(), "https://api.acme.test", List.of("read:orders")).get("sub").asText());
        assertEquals("insufficient_scope", assertThrows(HostedLoginException.class,
                () -> login.verifyAccessToken(tokens.accessToken(), "https://api.acme.test", List.of("write:orders"))).errorCode());
        assertThrows(HostedLoginException.class, () -> login.verifyAccessToken(tokens.idToken(), CLIENT_ID, null));
    }

    @Test
    void refusals() {
        HostedLogin login = login(null);
        HostedLogin.AuthorizationRequest req = login.authorizationUrl(null);
        String[] a = tenant.authorize(req.url());
        HostedLogin.CallbackChecks checks = new HostedLogin.CallbackChecks(req.state(), req.nonce(), req.codeVerifier());
        Map<Map<String, String>, String> cases = new LinkedHashMap<>();
        cases.put(Map.of("code", a[0], "state", "x"), "state_mismatch");
        cases.put(Map.of("error", "access_denied", "state", a[1]), "access_denied");
        cases.put(Map.of("code", a[0], "state", a[1], "iss", "https://evil"), "issuer_mismatch");
        cases.forEach((p, want) -> assertEquals(want, assertThrows(HostedLoginException.class, () -> login.handleCallback(p, checks)).errorCode()));

        tenant.nonceOverride = "replayed";
        HostedLogin.AuthorizationRequest req2 = login.authorizationUrl(null);
        String[] a2 = tenant.authorize(req2.url());
        assertEquals("nonce_mismatch", assertThrows(HostedLoginException.class, () -> login.handleCallback(Map.of("code", a2[0], "state", a2[1]),
                new HostedLogin.CallbackChecks(req2.state(), req2.nonce(), req2.codeVerifier()))).errorCode());
        tenant.nonceOverride = null;
        tenant.signWith = FakeTenant.rsa();
        HostedLogin.AuthorizationRequest req3 = login.authorizationUrl(null);
        String[] a3 = tenant.authorize(req3.url());
        HostedLoginException bad = assertThrows(HostedLoginException.class, () -> login.handleCallback(Map.of("code", a3[0], "state", a3[1]),
                new HostedLogin.CallbackChecks(req3.state(), req3.nonce(), req3.codeVerifier())));
        assertTrue(bad.getMessage().contains("Bad signature"));
    }

    @Test
    void issThisIssuerOrNoneIsAcceptedAForeignOrEmptyOneIsRefusedBeforeTheExchange() {
        HostedLogin login = login(null);
        HostedLogin.AuthorizationRequest req = login.authorizationUrl(null);
        String[] a = tenant.authorize(req.url());
        HostedLogin.CallbackChecks checks = new HostedLogin.CallbackChecks(req.state(), req.nonce(), req.codeVerifier());
        for (String iss : List.of("https://evil", tenant.issuer + ".evil", tenant.issuer + "/", "")) {
            assertEquals("issuer_mismatch", assertThrows(HostedLoginException.class,
                    () -> login.handleCallback(Map.of("code", a[0], "state", a[1], "iss", iss), checks)).errorCode(), iss);
        }
        String state = java.net.URLEncoder.encode(a[1], StandardCharsets.UTF_8);
        assertEquals("issuer_mismatch", assertThrows(HostedLoginException.class,
                () -> login.handleCallback("https://app/cb?code=" + a[0] + "&state=" + state + "&iss=", checks)).errorCode());
        // A foreign error answer is reported as the issuer mismatch, not as its own error.
        assertEquals("issuer_mismatch", assertThrows(HostedLoginException.class,
                () -> login.handleCallback(Map.of("error", "access_denied", "state", a[1], "iss", "https://evil"), checks)).errorCode());
        assertTrue(tenant.posts.isEmpty());
        assertEquals("usr_1", login.handleCallback(Map.of("code", a[0], "state", a[1], "iss", tenant.issuer), checks).claims().get("sub").asText());

        // No iss (an older server): no field in the URL, or a null value for a missing field.
        HostedLogin.AuthorizationRequest req2 = login.authorizationUrl(null);
        String[] a2 = tenant.authorize(req2.url());
        Map<String, String> noIss = new HashMap<>(Map.of("code", a2[0], "state", a2[1]));
        noIss.put("iss", null);
        assertEquals("usr_1", login.handleCallback(noIss, new HostedLogin.CallbackChecks(req2.state(), req2.nonce(), req2.codeVerifier())).claims().get("sub").asText());
        HostedLogin.AuthorizationRequest req3 = login.authorizationUrl(null);
        String[] a3 = tenant.authorize(req3.url());
        assertEquals("usr_1", login.handleCallback("https://app/cb?code=" + a3[0] + "&state=" + java.net.URLEncoder.encode(a3[1], StandardCharsets.UTF_8),
                new HostedLogin.CallbackChecks(req3.state(), req3.nonce(), req3.codeVerifier())).claims().get("sub").asText());
    }

    @Test
    void exchangeTokenCibaAndTokenVault() {
        HostedLogin login = login("s3cret");
        HostedLogin.TokenSet ex = login.exchangeToken("user-at", "https://api.acme.test", "payments:create");
        assertEquals(List.of("at-x", "urn:ietf:params:oauth:token-type:access_token"), List.of(ex.accessToken(), ex.issuedTokenType()));
        assertEquals("user-at", HostedLogin.parseQuery(tenant.posts.get(0).body()).get("subject_token"));
        HostedLogin.UserApprovalRequest ask = login.askUser("ada@acme.test", "openid payments:create",
                new HostedLogin.AskUserOptions().bindingMessage("Pay invoice 42").authorizationDetails(List.of(Map.of("type", "payment_initiation"))));
        assertEquals(List.of("req-1", "42"), List.of(ask.authReqId(), ask.bindingCode()));
        JsonNode details = Json.parse("[{\"type\":\"payment_initiation\"}]");
        assertEquals(details, Json.parse(HostedLogin.parseQuery(tenant.posts.get(1).body()).get("authorization_details")));
        assertEquals(details, login.waitForUser(ask).authorizationDetails());
        tenant.polls = 0;
        assertEquals("access_denied", assertThrows(HostedLoginException.class,
                () -> login.waitForUser(new HostedLogin.UserApprovalRequest("denied", ask.expiresAt(), ask.interval(), null))).errorCode());
        HostedLogin.TokenSet vaulted = login.getConnectionToken("user-at", "google", "email");
        assertEquals(List.of("ya29.g", "google"), List.of(vaulted.accessToken(), vaulted.connection()));
        Map<String, String> last = HostedLogin.parseQuery(tenant.posts.get(tenant.posts.size() - 1).body());
        assertEquals("email", last.get("scope"));
        assertFalse(last.containsKey("audience"));
    }

    @Test
    void myAccountCallsAndStepUp() {
        MyAccount account = login(null).myAccount("at-me");
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("theme", null);
        ObjectNode updated = account.updateProfile(Map.of("name", "Ada", "userMetadata", metadata));
        assertEquals(Json.parse("{\"name\":\"Ada\",\"userMetadata\":{\"theme\":null}}"), updated.get("profile"));
        account.endSession("s1");
        MyAccountException e = assertThrows(MyAccountException.class, () -> account.setPassword("n3w-passw0rd"));
        assertTrue(e.isStepUp());
        assertEquals(List.of(401, 0), List.of(e.status(), e.maxAge()));
        assertEquals(tenant.issuer + "/account/security", account.accountPageUrl("security"));
    }

    @Test
    void sealedCookiesRoundTripSplitAndRefuseTampering() {
        String secret = "0123456789abcdef0123456789abcdef-cookie";
        String sealed = LoginSession.seal(Map.of("sub", "usr_1", "state", "s"), secret, "session", 60);
        assertEquals("usr_1", LoginSession.unseal(sealed, secret, "session").get("sub").asText());
        assertNull(LoginSession.unseal(sealed, secret, "tx"));
        assertNull(LoginSession.unseal(sealed.substring(0, sealed.length() - 2) + "AA", secret, "session"));
        assertNull(LoginSession.unseal(LoginSession.seal("x", secret, "session", -1), secret, "session"));
        assertThrows(TouchQueConfigException.class, () -> LoginSession.seal("x", "short", "session", 60));

        String big = LoginSession.seal("y".repeat(6000), secret, "session", 60);
        Map<String, String> cookies = LoginSession.cookieValues("tq_session", big, List.of("tq_session"));
        assertEquals(java.util.Set.of("tq_session", "tq_session.0", "tq_session.1", "tq_session.2"), cookies.keySet());
        assertNull(cookies.get("tq_session"));
        Map<String, String> sent = new HashMap<>(cookies);
        sent.remove("tq_session");
        assertEquals("y".repeat(6000), LoginSession.unseal(LoginSession.read("tq_session", sent), secret, "session").asText());
        assertEquals("/orders?id=1", LoginSession.safeReturnTo("/orders?id=1", "/"));
        assertEquals("/", LoginSession.safeReturnTo("//evil.example", "/"));
        assertEquals("/", LoginSession.safeReturnTo("https://evil.example", "/"));
    }
}
