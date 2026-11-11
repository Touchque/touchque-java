package com.touchque.login;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueOptions;
import com.touchque.crypto.Jws;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Touchque Login (hosted sign-in) for your app: an OpenID Connect client for your tenant. PKCE
 * (S256) is always used. ID tokens are checked against the tenant's JWKS (RS256, issuer,
 * audience, expiry, nonce, at_hash). Your API checks access tokens with
 * {@link #verifyAccessToken}. In Spring Boot, the Touchque starter wires the routes for you.
 *
 * <pre>{@code
 * var login = new HostedLogin(new HostedLogin.Options("acme.login.touchque.com", "…").clientSecret("…").redirectUri("https://app/callback"));
 * var req = login.authorizationUrl(null);   // keep state, nonce, codeVerifier; redirect to req.url()
 * var tokens = login.handleCallback(callbackUrl, new HostedLogin.CallbackChecks(req.state(), req.nonce(), req.codeVerifier()));
 * }</pre>
 */
public final class HostedLogin {
    /** requested_token_type for the token vault ({@link #getConnectionToken}). */
    public static final String CONNECTION_TOKEN_TYPE = "urn:touchque:params:oauth:token-type:connection-access-token";

    static final HttpClient SHARED_CLIENT = TouchqueHttp.createClient(Duration.ofSeconds(10));

    private final Options o;
    private final String issuer;
    private final HttpClient client;
    private final Object keysLock = new Object();
    private Map<String, JsonNode> keys = new HashMap<>();
    private Instant keysAt = Instant.EPOCH;

    /** Settings of a {@link HostedLogin}. */
    public static final class Options {
        private final String domain;
        private final String clientId;
        private String clientSecret;
        private String redirectUri;
        private String scope = "openid profile email";
        private String audience;
        private Duration clockTolerance = Duration.ofSeconds(60);
        private HttpClient httpClient;

        /**
         * @param domain your tenant: {@code acme.login.touchque.com} or your own domain.
         * @param clientId your app's client ID.
         */
        public Options(String domain, String clientId) {
            this.domain = domain;
            this.clientId = clientId;
        }

        /** Confidential apps (server side): sent with HTTP Basic. */
        public Options clientSecret(String v) {
            this.clientSecret = v;
            return this;
        }

        public Options redirectUri(String v) {
            this.redirectUri = v;
            return this;
        }

        /** Default {@code openid profile email}. */
        public Options scope(String v) {
            this.scope = v;
            return this;
        }

        /** The API the access token is for. */
        public Options audience(String v) {
            this.audience = v;
            return this;
        }

        public Options clockTolerance(Duration v) {
            this.clockTolerance = v;
            return this;
        }

        /** Your own HttpClient (never following redirects). */
        public Options httpClient(HttpClient v) {
            this.httpClient = v;
            return this;
        }
    }

    /** What an authorization request may carry besides the defaults. */
    public static final class AuthorizationOptions {
        private String state;
        private String nonce;
        private String codeVerifier;
        private String redirectUri;
        private String scope;
        private String audience;
        private String prompt;
        private String loginHint;
        private String screenHint;
        private String uiLocales;
        private Integer maxAge;
        private String connection;
        private String organization;
        private String invitation;
        private String acrValues;
        private String responseMode;
        private Map<String, String> extraParams;

        public AuthorizationOptions state(String v) {
            this.state = v;
            return this;
        }

        public AuthorizationOptions nonce(String v) {
            this.nonce = v;
            return this;
        }

        public AuthorizationOptions codeVerifier(String v) {
            this.codeVerifier = v;
            return this;
        }

        public AuthorizationOptions redirectUri(String v) {
            this.redirectUri = v;
            return this;
        }

        public AuthorizationOptions scope(String v) {
            this.scope = v;
            return this;
        }

        public AuthorizationOptions audience(String v) {
            this.audience = v;
            return this;
        }

        public AuthorizationOptions prompt(String v) {
            this.prompt = v;
            return this;
        }

        public AuthorizationOptions loginHint(String v) {
            this.loginHint = v;
            return this;
        }

        /** {@code signup} opens the sign-up form. */
        public AuthorizationOptions screenHint(String v) {
            this.screenHint = v;
            return this;
        }

        public AuthorizationOptions uiLocales(String v) {
            this.uiLocales = v;
            return this;
        }

        /** 0 forces a fresh sign-in (My Account step-up). */
        public AuthorizationOptions maxAge(Integer v) {
            this.maxAge = v;
            return this;
        }

        public AuthorizationOptions connection(String v) {
            this.connection = v;
            return this;
        }

        public AuthorizationOptions organization(String v) {
            this.organization = v;
            return this;
        }

        public AuthorizationOptions invitation(String v) {
            this.invitation = v;
            return this;
        }

        public AuthorizationOptions acrValues(String v) {
            this.acrValues = v;
            return this;
        }

        public AuthorizationOptions responseMode(String v) {
            this.responseMode = v;
            return this;
        }

        public AuthorizationOptions extraParams(Map<String, String> v) {
            this.extraParams = v;
            return this;
        }
    }

    /** Where to send the browser, and what to keep (in the session) until the callback. */
    public record AuthorizationRequest(String url, String state, String nonce, String codeVerifier) {
    }

    /** What the callback is checked against: the values kept from {@link #authorizationUrl}. */
    public record CallbackChecks(String state, String nonce, String codeVerifier, String redirectUri, Integer maxAge) {
        public CallbackChecks(String state, String nonce, String codeVerifier) {
            this(state, nonce, codeVerifier, null, null);
        }
    }

    /**
     * Tokens from the tenant. {@code expiresAt}: Unix seconds. {@code refreshToken} rotates: keep
     * the newest one. {@code claims}: the verified ID token's claims (sign-in, refresh).
     * {@code connection}: token vault, the connection the token is from.
     */
    public record TokenSet(String accessToken, String tokenType, long expiresAt, String scope, String idToken, String refreshToken, ObjectNode claims,
            JsonNode authorizationDetails, String issuedTokenType, String connection) {
        TokenSet withClaims(ObjectNode c) {
            return new TokenSet(accessToken, tokenType, expiresAt, scope, idToken, refreshToken, c, authorizationDetails, issuedTokenType, connection);
        }
    }

    /** What a CIBA request carries besides the user and scope. */
    public static final class AskUserOptions {
        private String audience;
        private String bindingMessage;
        private Object authorizationDetails;
        private Integer requestedExpiry;

        public AskUserOptions audience(String v) {
            this.audience = v;
            return this;
        }

        /** At most 64 characters, shown on the phone. */
        public AskUserOptions bindingMessage(String v) {
            this.bindingMessage = v;
            return this;
        }

        /** RFC 9396 authorization details (a Map, record or JsonNode). */
        public AskUserOptions authorizationDetails(Object v) {
            this.authorizationDetails = v;
            return this;
        }

        /** 30–300 seconds. */
        public AskUserOptions requestedExpiry(Integer v) {
            this.requestedExpiry = v;
            return this;
        }
    }

    /** A CIBA request waiting for the user; {@code expiresAt} in Unix seconds. */
    public record UserApprovalRequest(String authReqId, long expiresAt, int interval, String bindingCode) {
    }

    public HostedLogin(Options options) {
        if (options.domain == null || options.domain.isEmpty()) throw new HostedLoginException("config", "domain is required");
        if (options.clientId == null || options.clientId.isEmpty()) throw new HostedLoginException("config", "clientId is required");
        this.o = options;
        this.issuer = issuerOf(options.domain);
        this.client = options.httpClient != null ? options.httpClient : SHARED_CLIENT;
    }

    /**
     * The issuer URL for a domain ({@code acme.login.touchque.com} → https://acme.login.touchque.com). Plaintext
     * http:// only on this machine (localhost, 127.0.0.1, ::1, *.localhost), like the API's baseUrl: codes,
     * PKCE verifiers, the client secret and tokens would otherwise travel in the clear.
     *
     * @throws HostedLoginException {@code config} for http:// on any other host
     */
    public static String issuerOf(String domain) {
        String raw = domain.replaceAll("/+$", "");
        String lower = raw.toLowerCase(Locale.ROOT);
        if (!lower.startsWith("http://")) return lower.startsWith("https://") ? raw : "https://" + raw;
        String host;
        try {
            host = URI.create(raw).getHost();
        } catch (IllegalArgumentException e) {
            host = null;
        }
        if (host == null || !(TouchqueOptions.isLoopback(host) || host.toLowerCase(Locale.ROOT).endsWith(".localhost"))) {
            throw new HostedLoginException("config", "Refusing a plaintext http:// domain for \"" + (host != null ? host : raw)
                    + "\". Codes, tokens and the client secret would be sent in the clear: use https://.");
        }
        return raw;
    }

    /** The tenant's issuer URL. */
    public String issuer() {
        return issuer;
    }

    public String clientId() {
        return o.clientId;
    }

    public String redirectUri() {
        return o.redirectUri;
    }

    /** The URL to send the browser to, and the values to keep until the callback. */
    public AuthorizationRequest authorizationUrl(AuthorizationOptions options) {
        AuthorizationOptions a = options != null ? options : new AuthorizationOptions();
        String redirect = a.redirectUri != null ? a.redirectUri : o.redirectUri;
        if (redirect == null || redirect.isEmpty()) throw new HostedLoginException("config", "redirectUri is required");
        String state = a.state != null ? a.state : random(32);
        String nonce = a.nonce != null ? a.nonce : random(32);
        String verifier = a.codeVerifier != null ? a.codeVerifier : random(48);
        Map<String, String> p = new LinkedHashMap<>();
        p.put("response_type", "code");
        p.put("client_id", o.clientId);
        p.put("redirect_uri", redirect);
        p.put("scope", a.scope != null ? a.scope : o.scope);
        p.put("state", state);
        p.put("nonce", nonce);
        p.put("code_challenge", Base64Url.encode(Crypto.sha256(verifier.getBytes(StandardCharsets.US_ASCII))));
        p.put("code_challenge_method", "S256");
        p.put("audience", a.audience != null ? a.audience : o.audience);
        p.put("prompt", a.prompt);
        p.put("login_hint", a.loginHint);
        p.put("screen_hint", a.screenHint);
        p.put("ui_locales", a.uiLocales);
        p.put("max_age", a.maxAge == null ? null : a.maxAge.toString());
        p.put("connection", a.connection);
        p.put("organization", a.organization);
        p.put("invitation", a.invitation);
        p.put("acr_values", a.acrValues);
        p.put("response_mode", a.responseMode);
        if (a.extraParams != null) p.putAll(a.extraParams);
        StringBuilder url = new StringBuilder(issuer).append("/authorize?");
        boolean first = true;
        for (Map.Entry<String, String> e : p.entrySet()) {
            if (e.getValue() == null || e.getValue().isEmpty()) continue;
            if (!first) url.append('&');
            first = false;
            url.append(TouchqueHttp.seg(e.getKey())).append('=').append(TouchqueHttp.seg(e.getValue()));
        }
        return new AuthorizationRequest(url.toString(), state, nonce, verifier);
    }

    /**
     * Checks state (and iss), exchanges the code with the PKCE verifier, verifies the ID token.
     *
     * @param callback the callback URL (or its query string).
     */
    public TokenSet handleCallback(String callback, CallbackChecks checks) {
        return handleCallback(parseQuery(callback), checks);
    }

    /**
     * Checks state (and iss), exchanges the code with the PKCE verifier, verifies the ID token.
     *
     * @param parameters the callback's query or form fields.
     */
    public TokenSet handleCallback(Map<String, String> parameters, CallbackChecks checks) {
        String state = parameters.get("state");
        if (state == null || state.isEmpty() || checks.state() == null || checks.state().isEmpty() || !fixedEquals(checks.state(), state)) {
            throw new HostedLoginException("state_mismatch", "The state does not match this sign-in");
        }
        // RFC 9207: a response that carries iss (even an empty one) must name this issuer, the one the
        // ID token is checked against. Servers that do not send iss yet (no field, or a null value) are accepted.
        String iss = parameters.get("iss");
        if (iss != null && !iss.equals(issuer)) {
            throw new HostedLoginException("issuer_mismatch", iss.isEmpty() ? "The response has an empty iss" : "The response came from " + iss);
        }
        String error = parameters.get("error");
        if (error != null && !error.isEmpty()) throw new HostedLoginException(error, parameters.get("error_description"));
        String code = parameters.get("code");
        if (code == null || code.isEmpty()) throw new HostedLoginException("invalid_request", "The callback has no code");
        String redirect = checks.redirectUri() != null ? checks.redirectUri() : o.redirectUri;
        if (redirect == null || redirect.isEmpty()) throw new HostedLoginException("config", "redirectUri is required");
        TokenSet tokens = token(fields("grant_type", "authorization_code", "code", code, "redirect_uri", redirect, "code_verifier", checks.codeVerifier()));
        if (tokens.idToken() == null || tokens.idToken().isEmpty()) throw new HostedLoginException("invalid_token", "No ID token: ask for the openid scope");
        return tokens.withClaims(verifyIdToken(tokens.idToken(), checks.nonce(), tokens.accessToken(), checks.maxAge()));
    }

    /** A new access token and a rotated refresh token: keep the new one. */
    public TokenSet refresh(String refreshToken, String scope) {
        TokenSet tokens = token(fields("grant_type", "refresh_token", "refresh_token", refreshToken, "scope", scope));
        return tokens.idToken() == null || tokens.idToken().isEmpty() ? tokens : tokens.withClaims(verifyIdToken(tokens.idToken(), null, tokens.accessToken(), null));
    }

    /**
     * A token for the My Account API (audience https://&lt;domain&gt;/me/) from the refresh token
     * a first-party app holds. The refresh token rotates: keep the returned one. Scopes: read:me,
     * update:me, manage:me:security, delete:me (default {@code read:me update:me}).
     */
    public TokenSet myAccountToken(String refreshToken, String scope) {
        return token(fields("grant_type", "refresh_token", "refresh_token", refreshToken, "audience", issuer + "/me/", "scope",
                scope != null ? scope : "read:me update:me"));
    }

    /** The My Account API for the person holding {@code accessToken}. */
    public MyAccount myAccount(String accessToken) {
        return new MyAccount(issuer, accessToken, client);
    }

    /** The hosted account page (profile; security, devices or privacy). */
    public String accountUrl(String section) {
        return issuer + "/account" + (section == null || section.isEmpty() ? "" : "/" + section);
    }

    /** Machine to machine: an access token for your API with the app's own credentials. */
    public TokenSet clientCredentials(String audience, String scope) {
        return token(fields("grant_type", "client_credentials", "audience", audience, "scope", scope));
    }

    /**
     * RFC 8693: a signed-in user's access token, traded for one to call {@code audience} on their
     * behalf (sub = the user, act.sub = this app).
     */
    public TokenSet exchangeToken(String subjectToken, String audience, String scope) {
        return token(fields("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token", subjectToken,
                "subject_token_type", "urn:ietf:params:oauth:token-type:access_token", "audience", audience, "scope", scope));
    }

    /**
     * Token vault: the provider's own access token (Google, Microsoft, GitHub…) for the signed-in
     * user, from a connection that stores tokens. Touchque refreshes it; the refresh token never
     * leaves. invalid_grant: the user has not signed in with the connection since it started
     * storing tokens, or they stopped app access.
     */
    public TokenSet getConnectionToken(String userAccessToken, String connection, String scope) {
        return token(fields("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token", userAccessToken,
                "subject_token_type", "urn:ietf:params:oauth:token-type:access_token", "requested_token_type", CONNECTION_TOKEN_TYPE,
                "connection", connection, "scope", scope));
    }

    /** CIBA: asks the user (email or usr_ id) to approve on their phone. */
    public UserApprovalRequest askUser(String loginHint, String scope, AskUserOptions options) {
        AskUserOptions a = options != null ? options : new AskUserOptions();
        Answer res = post("/bc-authorize", fields("login_hint", loginHint, "scope", scope, "audience", a.audience, "binding_message", a.bindingMessage,
                "authorization_details", a.authorizationDetails == null ? null : Json.write(Json.toNode(a.authorizationDetails)),
                "requested_expiry", a.requestedExpiry == null ? null : a.requestedExpiry.toString()));
        if (res.status >= 400) throw error(res);
        ObjectNode d = Json.parseObject(res.body);
        Long expiresIn = Json.lng(d, "expires_in");
        Integer interval = Json.integer(d, "interval");
        return new UserApprovalRequest(orEmpty(Json.str(d, "auth_req_id")), Instant.now().getEpochSecond() + (expiresIn != null ? expiresIn : 0),
                interval != null ? interval : 5, Json.str(d, "binding_code"));
    }

    /** Polls until the user answers: the tokens, or {@link HostedLoginException} access_denied / expired_token. */
    public TokenSet waitForUser(UserApprovalRequest request) {
        int interval = request.interval();
        while (true) {
            if (Instant.now().getEpochSecond() > request.expiresAt()) throw new HostedLoginException("expired_token", "The user did not answer in time");
            try {
                Thread.sleep(Duration.ofSeconds(interval).toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new HostedLoginException("interrupted", null);
            }
            try {
                return token(fields("grant_type", "urn:openid:params:grant-type:ciba", "auth_req_id", request.authReqId()));
            } catch (HostedLoginException e) {
                if ("slow_down".equals(e.errorCode())) interval += 5;
                else if (!"authorization_pending".equals(e.errorCode())) throw e;
            }
        }
    }

    public void revoke(String token) {
        Answer res = post("/oauth/revoke", fields("token", token));
        if (res.status >= 400) throw error(res);
    }

    public ObjectNode userinfo(String accessToken) {
        Answer res = send(HttpRequest.newBuilder(URI.create(issuer + "/userinfo")).header("Authorization", "Bearer " + accessToken).GET());
        if (res.status >= 400) throw error(res);
        return Json.parseObject(res.body);
    }

    public String logoutUrl(String idTokenHint, String postLogoutRedirectUri, String state) {
        List<String> p = new ArrayList<>();
        p.add("client_id=" + TouchqueHttp.seg(o.clientId));
        if (idTokenHint != null && !idTokenHint.isEmpty()) p.add("id_token_hint=" + TouchqueHttp.seg(idTokenHint));
        if (postLogoutRedirectUri != null && !postLogoutRedirectUri.isEmpty()) p.add("post_logout_redirect_uri=" + TouchqueHttp.seg(postLogoutRedirectUri));
        if (state != null && !state.isEmpty()) p.add("state=" + TouchqueHttp.seg(state));
        return issuer + "/oidc/logout?" + String.join("&", p);
    }

    /** For your API: signature, issuer, audience, expiry, typ at+jwt, scopes. */
    public ObjectNode verifyAccessToken(String token, String audience, Collection<String> requiredScopes) {
        ObjectNode payload = verifyJwt(token, "at+jwt");
        if (!audiences(payload).contains(audience)) throw new HostedLoginException("invalid_token", "The token is for another audience");
        String scope = Json.str(payload, "scope");
        List<String> scopes = Arrays.asList((scope != null ? scope : "").split(" "));
        List<String> missing = new ArrayList<>();
        if (requiredScopes != null) {
            for (String s : requiredScopes) {
                if (!scopes.contains(s)) missing.add(s);
            }
        }
        if (!missing.isEmpty()) throw new HostedLoginException("insufficient_scope", "Missing scope: " + String.join(" ", missing), 403);
        return payload;
    }

    public ObjectNode verifyIdToken(String idToken, String nonce, String accessToken, Integer maxAge) {
        ObjectNode payload = verifyJwt(idToken, null);
        List<String> auds = audiences(payload);
        if (!auds.contains(o.clientId)) throw new HostedLoginException("invalid_token", "The ID token is for another app");
        if (auds.size() > 1 && !o.clientId.equals(Json.str(payload, "azp"))) throw new HostedLoginException("invalid_token", "azp does not name this app");
        if (nonce != null) {
            String got = Json.str(payload, "nonce");
            if (got == null || !fixedEquals(nonce, got)) throw new HostedLoginException("nonce_mismatch", "The nonce does not match this sign-in");
        }
        String atHash = Json.str(payload, "at_hash");
        if (accessToken != null && atHash != null) {
            String expected = Base64Url.encode(Arrays.copyOf(Crypto.sha256(accessToken.getBytes(StandardCharsets.US_ASCII)), 16));
            if (!fixedEquals(expected, atHash)) throw new HostedLoginException("invalid_token", "at_hash does not match the access token");
        }
        Long authTime = Json.lng(payload, "auth_time");
        if (maxAge != null && authTime != null && Instant.now().getEpochSecond() - authTime > maxAge + o.clockTolerance.getSeconds()) {
            throw new HostedLoginException("login_required", "The sign-in is older than maxAge");
        }
        return payload;
    }

    // ── internals ────────────────────────────────────────────────────────

    private static String random(int bytes) {
        return Base64Url.encode(Crypto.randomBytes(bytes));
    }

    static boolean fixedEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String orEmpty(String s) {
        return s != null ? s : "";
    }

    private static List<String> audiences(ObjectNode payload) {
        List<String> out = new ArrayList<>();
        JsonNode aud = payload.get("aud");
        if (aud != null && aud.isArray()) aud.forEach(a -> out.add(a.isTextual() ? a.asText() : null));
        else out.add(Json.str(payload, "aud"));
        return out;
    }

    private static Map<String, String> fields(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    /** The fields of a callback URL's query (or of a bare query string). */
    public static Map<String, String> parseQuery(String callback) {
        String q = callback.contains("?") ? callback.substring(callback.indexOf('?') + 1) : callback;
        int hash = q.indexOf('#');
        if (hash >= 0) q = q.substring(0, hash);
        Map<String, String> d = new LinkedHashMap<>();
        for (String part : q.split("&")) {
            if (part.isEmpty()) continue;
            int i = part.indexOf('=');
            String k = URLDecoder.decode(i < 0 ? part : part.substring(0, i), StandardCharsets.UTF_8);
            String v = i < 0 ? "" : URLDecoder.decode(part.substring(i + 1), StandardCharsets.UTF_8);
            d.put(k, v);
        }
        return d;
    }

    record Answer(int status, String body) {
    }

    static Answer send(HttpClient client, HttpRequest.Builder req) {
        req.timeout(Duration.ofSeconds(10)).header("Accept", "application/json");
        try {
            HttpResponse<InputStream> res = client.send(req.build(), HttpResponse.BodyHandlers.ofInputStream());
            return new Answer(res.statusCode(), TouchqueHttp.readLimited(res.body()));
        } catch (IOException e) {
            throw new HostedLoginException("network_error", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HostedLoginException("network_error", "interrupted");
        }
    }

    private Answer send(HttpRequest.Builder req) {
        return send(client, req);
    }

    private Answer post(String path, Map<String, String> fields) {
        Map<String, String> form = new LinkedHashMap<>();
        fields.forEach((k, v) -> {
            if (v != null && !v.isEmpty()) form.put(k, v);
        });
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(issuer + path)).header("Content-Type", "application/x-www-form-urlencoded");
        if (o.clientSecret != null) {
            String basic = URLEncoder.encode(o.clientId, StandardCharsets.UTF_8) + ":" + URLEncoder.encode(o.clientSecret, StandardCharsets.UTF_8);
            req.header("Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));
        } else {
            form.put("client_id", o.clientId);
        }
        StringBuilder body = new StringBuilder();
        form.forEach((k, v) -> {
            if (body.length() > 0) body.append('&');
            body.append(URLEncoder.encode(k, StandardCharsets.UTF_8)).append('=').append(URLEncoder.encode(v, StandardCharsets.UTF_8));
        });
        return send(req.POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8)));
    }

    private static HostedLoginException error(Answer res) {
        ObjectNode d = Json.parseObject(res.body);
        String err = Json.str(d, "error");
        return new HostedLoginException(err != null ? err : "http_" + res.status, Json.str(d, "error_description"), res.status);
    }

    private TokenSet token(Map<String, String> fields) {
        Answer res = post("/oauth/token", fields);
        if (res.status >= 400) throw error(res);
        ObjectNode d = Json.parseObject(res.body);
        Long expiresIn = Json.lng(d, "expires_in");
        String tokenType = Json.str(d, "token_type");
        return new TokenSet(orEmpty(Json.str(d, "access_token")), tokenType != null ? tokenType : "Bearer",
                Instant.now().getEpochSecond() + (expiresIn != null ? expiresIn : 0), orEmpty(Json.str(d, "scope")), Json.str(d, "id_token"),
                Json.str(d, "refresh_token"), Json.object(), d.get("authorization_details") instanceof ArrayNode ad ? ad.deepCopy() : null,
                Json.str(d, "issued_token_type"), Json.str(d, "connection"));
    }

    private void loadKeys(boolean force) {
        synchronized (keysLock) {
            Duration age = Duration.between(keysAt, Instant.now());
            if (!force && !keys.isEmpty() && age.toMinutes() < 60) return;
            if (force && age.toSeconds() < 30) return;
            Answer res = send(HttpRequest.newBuilder(URI.create(issuer + "/.well-known/jwks.json")).GET());
            if (res.status >= 400) throw new HostedLoginException("jwks_unavailable", "JWKS answered " + res.status);
            Map<String, JsonNode> loaded = new HashMap<>();
            JsonNode list = Json.parseObject(res.body).get("keys");
            if (list != null && list.isArray()) {
                for (JsonNode k : list) {
                    String kid = Json.str(k, "kid");
                    String use = Json.str(k, "use");
                    if ("RSA".equals(Json.str(k, "kty")) && kid != null && !kid.isEmpty() && Json.str(k, "n") != null && Json.str(k, "e") != null
                            && (use == null || use.equals("sig"))) {
                        loaded.put(kid, k);
                    }
                }
            }
            keys = loaded;
            keysAt = Instant.now();
        }
    }

    private ObjectNode verifyJwt(String token, String typ) {
        Jws.Parts parts = Jws.split(token);
        if (parts == null) throw new HostedLoginException("invalid_token", "not a JWT");
        ObjectNode header = parts.header();
        ObjectNode payload = parts.claims();
        if (!"RS256".equals(Json.str(header, "alg"))) throw new HostedLoginException("invalid_token", "Unexpected alg");
        String headerTyp = Json.str(header, "typ");
        if (typ != null && !(headerTyp != null ? headerTyp : "").toLowerCase(Locale.ROOT).equals(typ)) {
            throw new HostedLoginException("invalid_token", "Wrong token type");
        }
        String kid = orEmpty(Json.str(header, "kid"));
        loadKeys(false);
        JsonNode key;
        synchronized (keysLock) {
            key = keys.get(kid);
        }
        if (key == null) {
            loadKeys(true);
            synchronized (keysLock) {
                key = keys.get(kid);
            }
        }
        if (key == null) throw new HostedLoginException("invalid_token", "Unknown signing key");
        if (!Jws.verify("RS256", key, parts.input(), parts.signature())) throw new HostedLoginException("invalid_token", "Bad signature");
        long now = Instant.now().getEpochSecond();
        long tolerance = o.clockTolerance.getSeconds();
        if (!issuer.equals(Json.str(payload, "iss"))) throw new HostedLoginException("invalid_token", "Wrong issuer");
        Long exp = Json.lng(payload, "exp");
        if (exp == null || now > exp + tolerance) throw new HostedLoginException("invalid_token", "The token expired");
        Long iat = Json.lng(payload, "iat");
        if (iat != null && iat > now + tolerance) throw new HostedLoginException("invalid_token", "The token is from the future");
        return payload;
    }
}
