package com.touchque.agents;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueApiException;
import com.touchque.TouchqueFeatureException;
import com.touchque.TouchqueApprovalException;
import com.touchque.TouchqueConfigException;
import com.touchque.TouchqueNetworkException;
import com.touchque.TouchqueOptions;
import com.touchque.TouchqueTimeoutException;
import com.touchque.crypto.AgentKeys;
import com.touchque.crypto.SigningKey;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * The agent side: an AI agent calls Touchque with its OWN key, never with your API key. It
 * signs a private_key_jwt assertion (RFC 7523) for a 10-minute token bound to its key with
 * DPoP (RFC 9449), and proves the key on every call, so a stolen token is useless on its own.
 *
 * <pre>{@code
 * var agent = new TouchqueAgent();      // TQ_AGENT_ID, TQ_AGENT_KEY
 * var approved = agent.requireApproval("ayse@example.com", "PAY_INVOICE", payment, null,
 *     s -> System.out.println("Type " + s.challengeCode() + " on your phone"), null);
 * }</pre>
 *
 * Thread-safe; create one per agent and reuse it.
 */
public final class TouchqueAgent {
    public static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static final Pattern AGENT_ID = Pattern.compile("^agt_[a-z2-9]{20}$");
    private static final Set<String> ENDED = Set.of("rejected", "blocked", "revoked", "expired", "stale", "redeemed");

    private final String agentId;
    private final SigningKey key;
    private final String kid;
    private final String baseUrl;
    private final String scope;
    private final Duration timeout;
    private final HttpClient client;
    private final Object tokenLock = new Object();
    private String token;
    private Instant tokenExpiresAt = Instant.EPOCH;

    /** Settings of a {@link TouchqueAgent}; null falls back to the environment. */
    public static final class Options {
        private String agentId;
        private Object privateKey;
        private String kid;
        private String baseUrl;
        private String scope;
        private Duration timeout = Duration.ofSeconds(10);
        private HttpClient httpClient;

        /** The {@code agt_…} id from {@code tq.agents().create(…)} (default: TQ_AGENT_ID). */
        public Options agentId(String v) {
            this.agentId = v;
            return this;
        }

        /** The agent's private key: a JWK (JsonNode or its JSON text) or an EC P-256 PKCS#8 PEM (default: TQ_AGENT_KEY). */
        public Options privateKey(Object v) {
            this.privateKey = v;
            return this;
        }

        /** The kid it was registered with (default: the JWK's kid, else its RFC 7638 thumbprint). */
        public Options kid(String v) {
            this.kid = v;
            return this;
        }

        /** The API's address (default: TQ_API_URL, else https://api.touchque.com). */
        public Options baseUrl(String v) {
            this.baseUrl = v;
            return this;
        }

        /** Scopes to ask for (default: all the agent has). */
        public Options scope(String v) {
            this.scope = v;
            return this;
        }

        public Options timeout(Duration v) {
            this.timeout = v;
            return this;
        }

        /** Your own HttpClient (never following redirects). */
        public Options httpClient(HttpClient v) {
            this.httpClient = v;
            return this;
        }
    }

    /** An agent from the environment (TQ_AGENT_ID, TQ_AGENT_KEY, TQ_API_URL). */
    public TouchqueAgent() {
        this(new Options());
    }

    public TouchqueAgent(Options options) {
        String id = options.agentId != null ? options.agentId : env("TQ_AGENT_ID");
        if (id == null || !AGENT_ID.matcher(id).matches()) {
            throw new TouchqueConfigException("Set TQ_AGENT_ID (or agentId): the agt_… id from agents().create()");
        }
        this.agentId = id;
        Object privateKey = options.privateKey != null ? options.privateKey : env("TQ_AGENT_KEY");
        if (privateKey == null || (privateKey instanceof String s && s.isEmpty())) {
            throw new TouchqueConfigException("Set TQ_AGENT_KEY (or privateKey): the agent's private key");
        }
        this.key = SigningKey.load(privateKey, "TouchqueAgent");
        this.kid = options.kid != null ? options.kid : jwkKid(privateKey, key);
        String url = options.baseUrl != null ? options.baseUrl : env("TQ_API_URL");
        if (url == null || url.isEmpty()) url = TouchqueOptions.DEFAULT_BASE_URL;
        this.baseUrl = url.replaceAll("/+$", "");
        TouchqueOptions.assertSafeBaseUrl(this.baseUrl, "baseUrl");
        this.scope = options.scope;
        this.timeout = options.timeout != null && !options.timeout.isZero() && !options.timeout.isNegative() ? options.timeout : Duration.ofSeconds(10);
        this.client = options.httpClient != null ? options.httpClient : TouchqueHttp.createClient(this.timeout);
    }

    static String env(String name) {
        String v = System.getenv(name);
        return v == null || v.isEmpty() ? null : v;
    }

    /** The kid of a JWK given as the key, else the public key's thumbprint. */
    static String jwkKid(Object privateKey, SigningKey key) {
        JsonNode jwk = null;
        if (privateKey instanceof JsonNode n) jwk = n;
        else if (privateKey instanceof String s && s.trim().startsWith("{")) jwk = Json.parse(s);
        String kid = jwk != null ? Json.str(jwk, "kid") : null;
        return kid != null ? kid : AgentKeys.thumbprint(key.publicJwk());
    }

    public String agentId() {
        return agentId;
    }

    /** The agent's current token (renewed a minute before it expires). */
    public String accessToken() {
        synchronized (tokenLock) {
            if (token != null && Duration.between(Instant.now(), tokenExpiresAt).getSeconds() > 60) return token;
            return fetchToken();
        }
    }

    private String fetchToken() {
        String url = baseUrl + "/agents/token";
        long now = Instant.now().getEpochSecond();
        ObjectNode claims = Json.object().put("iss", agentId).put("sub", agentId).put("aud", url).put("iat", now).put("exp", now + 60).put("jti", Crypto.randomHex(16));
        String assertion = key.jws(Json.object().put("typ", "JWT").put("kid", kid), claims);
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "client_credentials");
        form.put("client_assertion_type", ASSERTION_TYPE);
        form.put("client_assertion", assertion);
        if (scope != null && !scope.isEmpty()) form.put("scope", scope);
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("DPoP", dpopProof(key, "POST", url, null))
                .POST(HttpRequest.BodyPublishers.ofString(form(form), StandardCharsets.UTF_8));
        Answer a = send(client, req, timeout, "agent");
        if (a.status != 200) throw failure(a.status, a.data);
        String t = Json.str(a.data, "access_token");
        if (t == null) throw failure(a.status, a.data);
        Long expiresIn = Json.lng(a.data, "expires_in");
        token = t;
        tokenExpiresAt = Instant.now().plusSeconds(expiresIn != null ? expiresIn : 600);
        return t;
    }

    /** A DPoP proof (RFC 9449) for one call: {@code htu} is the URL without its query or fragment. */
    static String dpopProof(SigningKey key, String method, String url, String accessToken) {
        ObjectNode claims = Json.object().put("htm", method.toUpperCase(java.util.Locale.ROOT)).put("htu", url.split("[?#]", 2)[0]).put("iat", Instant.now().getEpochSecond()).put("jti", Crypto.randomHex(16));
        if (accessToken != null) claims.put("ath", AgentKeys.accessTokenHash(accessToken));
        ObjectNode header = Json.object().put("typ", "dpop+jwt");
        header.set("jwk", key.publicJwk());
        return key.jws(header, claims);
    }

    static String form(Map<String, String> fields) {
        StringBuilder sb = new StringBuilder();
        fields.forEach((k, v) -> {
            if (v == null) return;
            if (sb.length() > 0) sb.append('&');
            sb.append(URLEncoder.encode(k, StandardCharsets.UTF_8)).append('=').append(URLEncoder.encode(v, StandardCharsets.UTF_8));
        });
        return sb.toString();
    }

    record Answer(int status, ObjectNode data) {
    }

    static Answer send(HttpClient client, HttpRequest.Builder req, Duration timeout, String who) {
        req.timeout(timeout).header("Accept", "application/json").header("User-Agent", "touchque-java-sdk/" + TouchqueHttp.SDK_VERSION + " " + who);
        try {
            HttpResponse<InputStream> res = client.send(req.build(), HttpResponse.BodyHandlers.ofInputStream());
            JsonNode parsed = Json.parse(TouchqueHttp.readLimited(res.body()));
            return new Answer(res.statusCode(), parsed instanceof ObjectNode o ? o : Json.object());
        } catch (HttpTimeoutException e) {
            throw new TouchqueNetworkException("timed out", e);
        } catch (IOException e) {
            throw new TouchqueNetworkException(String.valueOf(e.getMessage()), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TouchqueNetworkException("interrupted", e);
        }
    }

    /** An OAuth error answer as a {@link TouchqueApiException}: {@code error} becomes its code. */
    static TouchqueApiException failure(int status, ObjectNode data) {
        if (!data.has("code") && Json.str(data, "error") != null) data.put("code", Json.str(data, "error"));
        if (!data.has("retryAfter") && Json.integer(data, "retry_after") != null) data.put("retryAfter", Json.integer(data, "retry_after"));
        String message = Json.str(data, "error_description") != null ? Json.str(data, "error_description")
                : Json.str(data, "error") != null ? Json.str(data, "error") : "Touchque API error: HTTP " + status;
        return TouchqueFeatureException.of(status, data, message);
    }

    /** A call with the agent's token and a fresh DPoP proof; one retry with a new token when Touchque no longer knows it. */
    private ObjectNode request(String method, String path, JsonNode body, boolean retried) {
        String current = accessToken();
        String url = baseUrl + path;
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", "DPoP " + current)
                .header("DPoP", dpopProof(key, method, url, current));
        if (body != null) {
            req.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(Json.write(body), StandardCharsets.UTF_8));
        } else {
            req.method(method, HttpRequest.BodyPublishers.noBody());
        }
        Answer a = send(client, req, timeout, "agent");
        if (a.status == 401 && !retried && "invalid_token".equals(Json.str(a.data, "code"))) {
            synchronized (tokenLock) {
                if (current.equals(token)) token = null;
            }
            return request(method, path, body, true);
        }
        if (a.status < 200 || a.status >= 300) throw failure(a.status, a.data);
        return a.data;
    }

    /** The agent as Touchque sees it: {@code agent} (id, name, allowedTypes, reviewAt, owner), {@code workspace}, {@code scope}. */
    public JsonNode me() {
        return request("GET", "/agents/me", null, false);
    }

    /**
     * Asks the person to approve on their Touchque phone. Show {@code challengeCode} in your
     * conversation (presence interactive, the default): the person types it on the phone.
     * Touchque draws the phone's rows from {@code authorizationDetails} (RFC 9396; a Map,
     * record or JsonNode).
     */
    public ApprovalState requestApproval(String user, String type, Object authorizationDetails, ApprovalOptions options) {
        ObjectNode body = Json.object().put("externalUsername", user).put("type", type);
        body.set("authorizationDetails", Json.toNode(authorizationDetails));
        if (options != null) {
            Json.put(body, "reason", options.reason);
            Json.put(body, "presence", options.presence);
            Json.put(body, "expiresIn", options.expiresIn);
            Json.put(body, "locale", options.locale);
            Json.put(body, "referenceId", options.referenceId);
            Json.put(body, "clientIp", options.clientIp);
            Json.put(body, "userAgent", options.userAgent);
            Json.put(body, "mandateId", options.mandateId);
        }
        return TouchqueHttp.to(request("POST", "/agents/approvals", body, false), ApprovalState.class);
    }

    /**
     * Asks the person for a mandate: one approval on the phone for a bounded series of
     * requests. Once active, pass its id as {@link ApprovalOptions#mandateId}: no push.
     * Returns the mandate (mandateId, status, challengeCode, maxCount, maxTotal, used…).
     */
    public JsonNode requestMandate(String user, String type, int maxCount, MandateAmount maxTotal, MandateOptions options) {
        ObjectNode body = Json.object().put("externalUsername", user).put("type", type).put("maxCount", maxCount);
        body.set("maxTotal", maxTotal.toJson());
        if (options != null) {
            if (options.perRequest != null) body.set("perRequest", options.perRequest.toJson());
            if (options.recipients != null) body.set("recipients", Json.toNode(options.recipients));
            Json.put(body, "validFor", options.validFor);
            Json.put(body, "reason", options.reason);
            Json.put(body, "expiresIn", options.expiresIn);
            Json.put(body, "locale", options.locale);
        }
        return request("POST", "/agents/mandates", body, false);
    }

    /**
     * The token vault: a person's own access token at another service, for a connection that
     * names this agent. Touchque refreshes it; the refresh token never leaves.
     * {@link TouchqueApiException} not_connected when nothing is kept.
     */
    public ConnectionToken getConnectionToken(String user, String connection, String scope) {
        ObjectNode body = Json.object().put("externalUsername", user).put("connection", connection);
        Json.put(body, "scope", scope);
        return TouchqueHttp.to(request("POST", "/agents/vault/token", body, false), ConnectionToken.class);
    }

    /** A mandate's state and what is left. */
    public JsonNode getMandate(String mandateId) {
        return request("GET", "/agents/mandates/" + TouchqueHttp.seg(mandateId), null, false);
    }

    /** Gives up a mandate. */
    public JsonNode revokeMandate(String mandateId) {
        return request("POST", "/agents/mandates/" + TouchqueHttp.seg(mandateId) + "/revoke", Json.object(), false);
    }

    /** Where an approval request is; {@code approvalToken} once approved. */
    public ApprovalState getApproval(String approvalId) {
        return TouchqueHttp.to(request("GET", "/agents/approvals/" + TouchqueHttp.seg(approvalId), null, false), ApprovalState.class);
    }

    /**
     * Asks the person's phone and waits for the answer: the approved state (holding
     * {@code approvalToken}), or {@link TouchqueApprovalException} / a timeout (default 5
     * minutes). {@code onChallenge} gets the state while the phone waits: show its
     * {@code challengeCode} in the conversation. Put it in front of any tool call an agent
     * framework makes, so the call runs only after the person approved.
     */
    public ApprovalState requireApproval(String user, String type, Object authorizationDetails, ApprovalOptions options,
            Consumer<ApprovalState> onChallenge, Duration timeout) {
        ApprovalState asked = requestApproval(user, type, authorizationDetails, options);
        if ("approved".equals(asked.status()) && asked.approvalToken() != null && !asked.approvalToken().isEmpty()) return asked;
        if (asked.challengeCode() != null && !asked.challengeCode().isEmpty() && onChallenge != null) onChallenge.accept(asked);
        return waitForApproval(asked.approvalId(), timeout != null ? timeout : Duration.ofMinutes(5), null);
    }

    /**
     * Polls until the person approves (the state holding {@code approvalToken}). Throws
     * {@link TouchqueApprovalException} when it ends otherwise and {@link TouchqueTimeoutException}
     * after {@code timeout} (default 10 minutes). An approval given during a phone call stays
     * provisional until the phone confirms it.
     */
    public ApprovalState waitForApproval(String approvalId, Duration timeout, Duration interval) {
        Duration every = interval != null && interval.toMillis() > 500 ? interval : Duration.ofMillis(interval == null ? 2000 : 500);
        Duration limit = timeout != null ? timeout : Duration.ofMinutes(10);
        Instant end = Instant.now().plus(limit);
        while (true) {
            ApprovalState state = getApproval(approvalId);
            if ("approved".equals(state.status()) && state.approvalToken() != null && !state.approvalToken().isEmpty()) return state;
            if (ENDED.contains(state.status())) throw new TouchqueApprovalException(approvalId, state.status(), state.reason());
            if (Instant.now().plus(every).isAfter(end)) {
                throw new TouchqueTimeoutException("Touchque: approval '" + approvalId + "' was not approved within " + limit.getSeconds() + "s", approvalId);
            }
            sleep(every);
        }
    }

    static void sleep(Duration d) {
        try {
            Thread.sleep(d.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TouchqueNetworkException("interrupted", e);
        }
    }

    /** What an approval request carries besides the user, type and details. */
    public static final class ApprovalOptions {
        private String reason;
        private String presence;
        private Integer expiresIn;
        private String locale;
        private String referenceId;
        private String clientIp;
        private String userAgent;
        private String mandateId;

        /** Why the agent asks (shown on the phone marked unverified). */
        public ApprovalOptions reason(String v) {
            this.reason = v;
            return this;
        }

        /** interactive (default: the person is in the conversation) or background. */
        public ApprovalOptions presence(String v) {
            this.presence = v;
            return this;
        }

        public ApprovalOptions expiresIn(Integer v) {
            this.expiresIn = v;
            return this;
        }

        public ApprovalOptions locale(String v) {
            this.locale = v;
            return this;
        }

        public ApprovalOptions referenceId(String v) {
            this.referenceId = v;
            return this;
        }

        public ApprovalOptions clientIp(String v) {
            this.clientIp = v;
            return this;
        }

        public ApprovalOptions userAgent(String v) {
            this.userAgent = v;
            return this;
        }

        /** An active mandate: no push. */
        public ApprovalOptions mandateId(String v) {
            this.mandateId = v;
            return this;
        }
    }

    /** An amount in a currency, e.g. {@code new MandateAmount("TRY", "1000")}. */
    public record MandateAmount(String currency, String amount) {
        ObjectNode toJson() {
            return Json.object().put("currency", currency).put("amount", amount);
        }
    }

    /** A mandate's limits besides the count and the total. */
    public static final class MandateOptions {
        private MandateAmount perRequest;
        private List<String> recipients;
        private Integer validFor;
        private String reason;
        private Integer expiresIn;
        private String locale;

        public MandateOptions perRequest(MandateAmount v) {
            this.perRequest = v;
            return this;
        }

        /** IBANs (or other recipients) the mandate is limited to. */
        public MandateOptions recipients(List<String> v) {
            this.recipients = v;
            return this;
        }

        /** Seconds the mandate is valid for once approved. */
        public MandateOptions validFor(Integer v) {
            this.validFor = v;
            return this;
        }

        public MandateOptions reason(String v) {
            this.reason = v;
            return this;
        }

        public MandateOptions expiresIn(Integer v) {
            this.expiresIn = v;
            return this;
        }

        public MandateOptions locale(String v) {
            this.locale = v;
            return this;
        }
    }

    /**
     * An approval request's state. {@code status}: pending, approved, provisional, rejected,
     * blocked, revoked, expired, stale, redeemed. {@code challengeCode}: the number to show in
     * the conversation. {@code requiresPasskey}: over the policy's requirePasskeyAbove, the
     * person approves with a passkey on your page, not on the phone. {@code approvalToken}: once
     * approved, hand it to the partner's server, which redeems it once.
     * {@code secondApprover}/{@code secondChallengeCode}: four eyes.
     */
    public record ApprovalState(String approvalId, String status, String presence, String challengeCode, Boolean requiresPasskey,
            String expiresAt, String caseCode, String reason, String approvalToken, Integer tokenExpiresIn, String secondApprover,
            String secondChallengeCode, String mandateId, JsonNode mandate) {
    }

    /** A person's access token at another service (token vault). */
    public record ConnectionToken(@JsonProperty("access_token") String accessToken, @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") Integer expiresIn, String scope, String connection) {
    }
}
