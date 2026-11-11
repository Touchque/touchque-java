package com.touchque.agents;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueApiException;
import com.touchque.TouchqueConfigException;
import com.touchque.TouchqueOptions;
import com.touchque.TouchqueTimeoutException;
import com.touchque.crypto.SigningKey;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * An organization's AI agent on Touchque SSO (Organization → AI agents in the dashboard): it
 * gets 5-minute tokens for one of the organization's apps, proving who it is with its own key
 * (private_key_jwt) or with the token its platform already gives it, and binds each token to a
 * DPoP key made when it starts. The app checks the token with Touchque's JWKS and the DPoP proof
 * on every call.
 *
 * <pre>{@code
 * var agent = new TouchqueOrgAgent(new TouchqueOrgAgent.Options().agentId("oagt_…").privateKey(System.getenv("TQ_ORG_AGENT_KEY")));
 * Map<String, String> headers = agent.authorization("GET", "https://payments.acme.com/invoices", "tqapp_…", null);
 * // In a GitHub Actions job (permissions: id-token: write), with no key to store:
 * var ci = new TouchqueOrgAgent(new TouchqueOrgAgent.Options().agentId("oagt_…").assertion(TouchqueOrgAgent.githubActionsToken("touchque")));
 * }</pre>
 */
public final class TouchqueOrgAgent {
    private static final Pattern AGENT_ID = Pattern.compile("^oagt_[a-z2-9]{20}$");

    private final String agentId;
    private final String issuer;
    private final SigningKey key;
    private final String kid;
    private final Supplier<String> assertion;
    private final SigningKey dpopKey = SigningKey.newEs256();
    private final String resource;
    private final String scope;
    private final Duration timeout;
    private final HttpClient client;
    private final Map<String, Cached> tokens = new ConcurrentHashMap<>();

    private record Cached(Token token, Instant expiresAt) {
    }

    /** Settings of a {@link TouchqueOrgAgent}; null falls back to the environment. */
    public static final class Options {
        private String agentId;
        private String issuer;
        private Object privateKey;
        private String kid;
        private Supplier<String> assertion;
        private String resource;
        private String scope;
        private Duration timeout = Duration.ofSeconds(10);
        private HttpClient httpClient;

        /** The {@code oagt_…} id from Organization → AI agents (default: TQ_ORG_AGENT_ID). */
        public Options agentId(String v) {
            this.agentId = v;
            return this;
        }

        /** Touchque SSO (default: TQ_SSO_URL, else https://sso.touchque.com). */
        public Options issuer(String v) {
            this.issuer = v;
            return this;
        }

        /** The agent's own key: a JWK (JsonNode or JSON) or an EC P-256 PKCS#8 PEM (default: TQ_ORG_AGENT_KEY). */
        public Options privateKey(Object v) {
            this.privateKey = v;
            return this;
        }

        public Options kid(String v) {
            this.kid = v;
            return this;
        }

        /**
         * Or the token the agent's platform gives it (GitHub Actions, GitLab, Google Cloud, Azure,
         * Kubernetes): see {@link TouchqueOrgAgent#githubActionsToken}, {@link TouchqueOrgAgent#fileToken}.
         */
        public Options assertion(Supplier<String> v) {
            this.assertion = v;
            return this;
        }

        /** The app ({@code tqapp_…}) tokens are for by default. */
        public Options resource(String v) {
            this.resource = v;
            return this;
        }

        public Options scope(String v) {
            this.scope = v;
            return this;
        }

        public Options timeout(Duration v) {
            this.timeout = v;
            return this;
        }

        public Options httpClient(HttpClient v) {
            this.httpClient = v;
            return this;
        }
    }

    /** An agent from the environment (TQ_ORG_AGENT_ID, TQ_ORG_AGENT_KEY, TQ_SSO_URL). */
    public TouchqueOrgAgent() {
        this(new Options());
    }

    public TouchqueOrgAgent(Options options) {
        String id = options.agentId != null ? options.agentId : TouchqueAgent.env("TQ_ORG_AGENT_ID");
        if (id == null || !AGENT_ID.matcher(id).matches()) {
            throw new TouchqueConfigException("Set TQ_ORG_AGENT_ID (or agentId): the oagt_… id from Organization → AI agents");
        }
        this.agentId = id;
        String iss = options.issuer != null ? options.issuer : TouchqueAgent.env("TQ_SSO_URL");
        this.issuer = (iss != null ? iss : "https://sso.touchque.com").replaceAll("/+$", "");
        TouchqueOptions.assertSafeBaseUrl(this.issuer, "issuer");
        if (options.assertion != null) {
            this.assertion = options.assertion;
            this.key = null;
            this.kid = null;
        } else {
            Object privateKey = options.privateKey != null ? options.privateKey : TouchqueAgent.env("TQ_ORG_AGENT_KEY");
            if (privateKey == null || (privateKey instanceof String s && s.isEmpty())) {
                throw new TouchqueConfigException("Pass privateKey (or set TQ_ORG_AGENT_KEY), or assertion with the platform's token");
            }
            this.assertion = null;
            this.key = SigningKey.load(privateKey, "TouchqueOrgAgent");
            this.kid = options.kid != null ? options.kid : TouchqueAgent.jwkKid(privateKey, key);
        }
        this.resource = options.resource;
        this.scope = options.scope;
        this.timeout = options.timeout != null && !options.timeout.isZero() && !options.timeout.isNegative() ? options.timeout : Duration.ofSeconds(10);
        this.client = options.httpClient != null ? options.httpClient : TouchqueHttp.createClient(this.timeout);
    }

    public String agentId() {
        return agentId;
    }

    /** The token a GitHub Actions job may ask for (the job needs {@code permissions: id-token: write}). */
    public static Supplier<String> githubActionsToken(String audience) {
        return () -> {
            String url = TouchqueAgent.env("ACTIONS_ID_TOKEN_REQUEST_URL");
            String bearer = TouchqueAgent.env("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
            if (url == null || bearer == null) throw new TouchqueConfigException("Not in a GitHub Actions job with `permissions: id-token: write`");
            String full = url + (url.contains("?") ? "&" : "?") + "audience=" + URLEncoder.encode(audience != null ? audience : "touchque", StandardCharsets.UTF_8);
            HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(full)).header("Authorization", "Bearer " + bearer).GET();
            String value = Json.str(TouchqueAgent.send(TouchqueHttp.createClient(Duration.ofSeconds(10)), req, Duration.ofSeconds(10), "org-agent").data(), "value");
            if (value == null || value.isEmpty()) throw new TouchqueConfigException("GitHub gave no token");
            return value;
        };
    }

    /** A token the platform writes to a file and renews (a Kubernetes projected service account token…). */
    public static Supplier<String> fileToken(String path) {
        return () -> {
            try {
                return Files.readString(Path.of(path)).trim();
            } catch (IOException e) {
                throw new TouchqueConfigException("Could not read the token file " + path + ": " + e.getMessage());
            }
        };
    }

    /** A DPoP proof (RFC 9449) for one request: with the token, for a call to the app. */
    public String dpopProof(String method, String url, String accessToken) {
        return TouchqueAgent.dpopProof(dpopKey, method, url, accessToken);
    }

    private String clientAssertion() {
        if (assertion != null) return assertion.get();
        long now = Instant.now().getEpochSecond();
        return key.jws(Json.object().put("typ", "JWT").put("kid", kid), Json.object().put("iss", agentId).put("sub", agentId)
                .put("aud", issuer + "/sso/token").put("iat", now).put("exp", now + 60).put("jti", Crypto.randomHex(16)));
    }

    /** POSTs to the SSO with the agent's client assertion (and, at /sso/token, a DPoP proof). */
    private ObjectNode post(String path, Map<String, String> fields, boolean dpop) {
        String url = issuer + path;
        Map<String, String> form = new LinkedHashMap<>();
        form.put("client_id", agentId);
        form.put("client_assertion_type", TouchqueAgent.ASSERTION_TYPE);
        form.put("client_assertion", clientAssertion());
        fields.forEach((k, v) -> {
            if (v != null && !v.isEmpty()) form.put(k, v);
        });
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(TouchqueAgent.form(form), StandardCharsets.UTF_8));
        if (dpop) req.header("DPoP", dpopProof("POST", url, null));
        TouchqueAgent.Answer a = TouchqueAgent.send(client, req, timeout, "org-agent");
        if (a.status() != 200) throw TouchqueAgent.failure(a.status(), a.data());
        return a.data();
    }

    private static Token tokenOf(ObjectNode data) {
        Integer expiresIn = Json.integer(data, "expires_in");
        String scope = Json.str(data, "scope");
        return new Token(Json.str(data, "access_token") != null ? Json.str(data, "access_token") : "", "DPoP", expiresIn != null ? expiresIn : 300,
                scope != null ? scope : "", data.get("authorization_details") instanceof ArrayNode ad ? ad.deepCopy() : null);
    }

    private static Map<String, String> fields(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    /** A token for one app (renewed 30 seconds before it expires); null resource and scope take the defaults. */
    public Token getToken(String resource, String scope) {
        String r = resource != null ? resource : this.resource;
        String s = scope != null ? scope : this.scope;
        String cacheKey = (r != null ? r : "") + " " + (s != null ? s : "");
        Cached cached = tokens.get(cacheKey);
        if (cached != null && Duration.between(Instant.now(), cached.expiresAt).getSeconds() > 30) return cached.token;
        Token token = tokenOf(post("/sso/token", fields("grant_type", "client_credentials", "resource", r, "scope", s), true));
        tokens.put(cacheKey, new Cached(token, Instant.now().plusSeconds(token.expiresIn())));
        return token;
    }

    /** A token for the default app. */
    public Token getToken() {
        return getToken(null, null);
    }

    /** A token for a member, with their own access token for one of the agent's apps (RFC 8693): sub is the member, act the agent. */
    public Token exchangeToken(String subjectToken, String resource, String scope) {
        return tokenOf(post("/sso/token", fields("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token", subjectToken,
                "subject_token_type", "urn:ietf:params:oauth:token-type:access_token", "resource", resource != null ? resource : this.resource,
                "scope", scope != null ? scope : this.scope), true));
    }

    /**
     * The token vault: a member's own access token at another service (Google, Microsoft 365,
     * GitHub…) they connected on Touchque, for a connection that names this agent.
     * {@code subjectToken} is the member's token, as for {@link #exchangeToken}; {@code scope} may
     * only narrow what the member granted. {@link TouchqueApiException} invalid_grant: the member
     * has not connected it (or disconnected, or left).
     */
    public ConnectionToken getConnectionToken(String subjectToken, String connection, String scope) {
        ObjectNode data = post("/sso/token", fields("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token", subjectToken,
                "subject_token_type", "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type", "urn:touchque:params:oauth:token-type:connection-access-token", "connection", connection, "scope", scope), true);
        return new ConnectionToken(Json.str(data, "access_token") != null ? Json.str(data, "access_token") : "", "Bearer", Json.integer(data, "expires_in"),
                Json.str(data, "scope") != null ? Json.str(data, "scope") : "", Json.str(data, "connection") != null ? Json.str(data, "connection") : connection);
    }

    /**
     * Asks to open a shared account (its key, from Organization → AI agents → Access) for a
     * member. The member opens {@code openUrl} in the browser where their Touchque extension is
     * paired; their phone approves with this agent named and the extension signs in there. The
     * agent never sees the password. {@code message} (at most 64 characters) is shown marked unverified.
     */
    public SharedAccountAsk askToOpenSharedAccount(String account, String loginHint, String message) {
        ObjectNode data = post("/sso/agents/shared-accounts/asks", fields("account", account, "login_hint", loginHint, "binding_message", message), false);
        Integer expiresIn = Json.integer(data, "expires_in");
        return new SharedAccountAsk(orEmpty(Json.str(data, "ask_id")), orEmpty(Json.str(data, "open_url")), orEmpty(Json.str(data, "status")),
                expiresIn != null ? expiresIn : 600);
    }

    /** Where an ask stands; never anything of the account. */
    public SharedAccountAskStatus sharedAccountAskStatus(String askId) {
        ObjectNode data = post("/sso/agents/shared-accounts/asks/" + TouchqueHttp.seg(askId), Map.of(), false);
        return new SharedAccountAskStatus(orEmpty(Json.str(data, "status")), Json.str(data, "reason"), Json.str(data, "case_code"));
    }

    /** Polls an ask until it ends: opened, refused, declined or expired (every 3 seconds by default). */
    public SharedAccountAskStatus waitForSharedAccount(SharedAccountAsk ask, Duration interval) {
        Instant deadline = Instant.now().plusSeconds(ask.expiresIn() + 5L);
        while (true) {
            SharedAccountAskStatus s = sharedAccountAskStatus(ask.askId());
            boolean waiting = "waiting_member".equals(s.status()) || "asked_phone".equals(s.status());
            if (!waiting || Instant.now().isAfter(deadline)) return s;
            TouchqueAgent.sleep(interval != null ? interval : Duration.ofSeconds(3));
        }
    }

    /** Asks a member to approve on their phone (CIBA). Show {@code bindingCode} in the conversation. */
    public MemberRequest askMember(String loginHint, AskMemberOptions options) {
        AskMemberOptions o = options != null ? options : new AskMemberOptions();
        ObjectNode data = post("/sso/bc-authorize", fields("login_hint", loginHint, "binding_message", o.bindingMessage,
                "resource", o.resource != null ? o.resource : resource, "scope", o.scope != null ? o.scope : scope,
                "authorization_details", o.authorizationDetails == null ? null : Json.write(Json.toNode(o.authorizationDetails)),
                "requested_expiry", o.requestedExpiry == null ? null : o.requestedExpiry.toString()), false);
        Integer expiresIn = Json.integer(data, "expires_in");
        Integer interval = Json.integer(data, "interval");
        return new MemberRequest(orEmpty(Json.str(data, "auth_req_id")), expiresIn != null ? expiresIn : 300, interval != null ? interval : 5,
                Json.str(data, "binding_code"));
    }

    /**
     * The member's answer (polling at the interval, slower when asked): the token once they
     * approve; {@link TouchqueApiException} access_denied or expired_token otherwise,
     * {@link TouchqueTimeoutException} after it expired.
     */
    public Token waitForMember(MemberRequest request) {
        int interval = Math.max(1, request.interval());
        Instant deadline = Instant.now().plusSeconds(request.expiresIn() + 5L);
        while (Instant.now().isBefore(deadline)) {
            TouchqueAgent.sleep(Duration.ofSeconds(interval));
            try {
                return tokenOf(post("/sso/token", fields("grant_type", "urn:openid:params:grant-type:ciba", "auth_req_id", request.authReqId()), true));
            } catch (TouchqueApiException e) {
                if ("slow_down".equals(e.code())) interval += 5;
                else if (!"authorization_pending".equals(e.code())) throw e;
            }
        }
        throw new TouchqueTimeoutException("The member did not answer in time", request.authReqId());
    }

    /** The two headers for one call to the app: {@code Authorization: DPoP …} and {@code DPoP}. */
    public Map<String, String> authorization(String method, String url, String resource, String scope) {
        String token = getToken(resource, scope).accessToken();
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "DPoP " + token);
        headers.put("DPoP", dpopProof(method, url, token));
        return headers;
    }

    /** Sets {@code Authorization: DPoP …} and a fresh DPoP proof on a request to the app. */
    public HttpRequest.Builder authorize(HttpRequest.Builder request, String method, String url, String resource, String scope) {
        authorization(method, url, resource, scope).forEach(request::setHeader);
        return request;
    }

    private static String orEmpty(String s) {
        return s != null ? s : "";
    }

    /** A DPoP-bound access token for one app. {@code authorizationDetails}: CIBA, what the member approved. */
    public record Token(String accessToken, String tokenType, int expiresIn, String scope, JsonNode authorizationDetails) {
    }

    /** A member's own access token at another service (token vault); {@code expiresIn} is null when the service does not say. */
    public record ConnectionToken(String accessToken, String tokenType, Integer expiresIn, String scope, String connection) {
    }

    public record SharedAccountAsk(String askId, String openUrl, String status, int expiresIn) {
    }

    /** {@code status}: waiting_member, asked_phone, opened, refused, declined or expired. */
    public record SharedAccountAskStatus(String status, String reason, String caseCode) {
    }

    /** A CIBA request waiting for the member. */
    public record MemberRequest(String authReqId, int expiresIn, int interval, String bindingCode) {
    }

    /** What a CIBA request carries besides the member. */
    public static final class AskMemberOptions {
        private String bindingMessage;
        private Object authorizationDetails;
        private String resource;
        private String scope;
        private Integer requestedExpiry;

        public AskMemberOptions bindingMessage(String v) {
            this.bindingMessage = v;
            return this;
        }

        /** RFC 9396 authorization details (a Map, record or JsonNode). */
        public AskMemberOptions authorizationDetails(Object v) {
            this.authorizationDetails = v;
            return this;
        }

        public AskMemberOptions resource(String v) {
            this.resource = v;
            return this;
        }

        public AskMemberOptions scope(String v) {
            this.scope = v;
            return this;
        }

        public AskMemberOptions requestedExpiry(Integer v) {
            this.requestedExpiry = v;
            return this;
        }
    }
}
