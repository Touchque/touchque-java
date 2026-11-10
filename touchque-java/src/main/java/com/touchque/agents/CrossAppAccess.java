package com.touchque.agents;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchQueConfigException;
import com.touchque.TouchQueIdJagException;
import com.touchque.TouchQueOptions;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
 * draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An organization's identity
 * provider (TouchQue SSO) decides which of its apps may reach which other service for its
 * members; the app trades a member's ID token for an ID-JAG there, then the ID-JAG for an access
 * token at the other service's authorization server, with no consent screen per member. Your own
 * authorization server takes them with {@link IdJagVerifier}.
 *
 * <pre>{@code
 * var jag = CrossAppAccess.requestIdJag(new CrossAppAccess.RequestOptions(id, secret, idToken, "https://auth.files.example")
 *     .issuer("https://sso.touchque.com"));
 * JsonNode tokens = CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions("https://auth.files.example/token", "acme", jag.assertion())
 *     .clientSecret(filesSecret));
 * }</pre>
 */
public final class CrossAppAccess {
    public static final String ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag";
    public static final String ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
    public static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private static final HttpClient SHARED_CLIENT = TouchQueHttp.createClient(Duration.ofSeconds(10));

    private CrossAppAccess() {
    }

    /** What {@link #requestIdJag} needs. */
    public static final class RequestOptions {
        private final String clientId;
        private final String clientSecret;
        private final String idToken;
        private final String audience;
        private String issuer;
        private String tokenEndpoint;
        private String resource;
        private String scope;

        /**
         * @param clientId your app at the identity provider ({@code tqapp_…} at TouchQue SSO).
         * @param clientSecret its secret.
         * @param idToken the member's ID token the identity provider issued to your app.
         * @param audience the other service's authorization server (its issuer).
         */
        public RequestOptions(String clientId, String clientSecret, String idToken, String audience) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.idToken = idToken;
            this.audience = audience;
        }

        /** The identity provider's issuer (its token endpoint is discovered), or give {@link #tokenEndpoint}. */
        public RequestOptions issuer(String v) {
            this.issuer = v;
            return this;
        }

        public RequestOptions tokenEndpoint(String v) {
            this.tokenEndpoint = v;
            return this;
        }

        public RequestOptions resource(String v) {
            this.resource = v;
            return this;
        }

        public RequestOptions scope(String v) {
            this.scope = v;
            return this;
        }
    }

    /** What {@link #redeemIdJag} needs. */
    public static final class RedeemOptions {
        private final String tokenEndpoint;
        private final String clientId;
        private final String assertion;
        private String clientSecret;
        private String resource;
        private String scope;

        public RedeemOptions(String tokenEndpoint, String clientId, String assertion) {
            this.tokenEndpoint = tokenEndpoint;
            this.clientId = clientId;
            this.assertion = assertion;
        }

        /** Without a secret the client is public: its client_id goes in the form. */
        public RedeemOptions clientSecret(String v) {
            this.clientSecret = v;
            return this;
        }

        public RedeemOptions resource(String v) {
            this.resource = v;
            return this;
        }

        public RedeemOptions scope(String v) {
            this.scope = v;
            return this;
        }
    }

    /** An ID-JAG the identity provider issued. */
    public record IdJagGrant(String assertion, Integer expiresIn, String scope) {
    }

    /** https, or http on this machine (tests). */
    static boolean safeUrl(String url) {
        try {
            URI u = URI.create(url);
            if (u.getHost() == null) return false;
            return "https".equals(u.getScheme()) || ("http".equals(u.getScheme()) && TouchQueOptions.isLoopback(u.getHost()));
        } catch (IllegalArgumentException | NullPointerException e) {
            return false;
        }
    }

    /** A JSON document by GET (never following redirects). */
    static JsonNode getJson(String url) {
        try {
            HttpResponse<InputStream> res = SHARED_CLIENT.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                    .header("Accept", "application/json").GET().build(), HttpResponse.BodyHandlers.ofInputStream());
            String text = TouchQueHttp.readLimited(res.body());
            if (res.statusCode() >= 400) throw new IllegalStateException(url + " answered " + res.statusCode());
            JsonNode parsed = Json.parse(text);
            return parsed instanceof ObjectNode ? parsed : Json.object();
        } catch (IOException e) {
            throw new IllegalStateException(e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    /** The identity provider's OpenID configuration, checked against its issuer. */
    static JsonNode discover(String issuer, Function<String, JsonNode> fetch) {
        JsonNode meta = fetch.apply(issuer.replaceAll("/+$", "") + "/.well-known/openid-configuration");
        if (!issuer.equals(Json.str(meta, "issuer"))) throw new TouchQueConfigException("the identity provider's metadata does not match its issuer");
        return meta;
    }

    private static ObjectNode postForm(String url, Map<String, String> form, String basicId, String basicSecret) {
        if (!safeUrl(url)) throw new TouchQueConfigException(url + " must be an https URL");
        StringBuilder body = new StringBuilder();
        form.forEach((k, v) -> {
            if (v == null) return;
            if (body.length() > 0) body.append('&');
            body.append(URLEncoder.encode(k, StandardCharsets.UTF_8)).append('=').append(URLEncoder.encode(v, StandardCharsets.UTF_8));
        });
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8));
        if (basicId != null) {
            String raw = URLEncoder.encode(basicId, StandardCharsets.UTF_8) + ":" + URLEncoder.encode(basicSecret, StandardCharsets.UTF_8);
            req.header("Authorization", "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8)));
        }
        int status;
        JsonNode parsed;
        try {
            HttpResponse<InputStream> res = SHARED_CLIENT.send(req.build(), HttpResponse.BodyHandlers.ofInputStream());
            status = res.statusCode();
            parsed = Json.parse(TouchQueHttp.readLimited(res.body()));
        } catch (IOException e) {
            throw new TouchQueIdJagException("temporarily_unavailable", url + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TouchQueIdJagException("temporarily_unavailable", "interrupted");
        }
        ObjectNode data = parsed instanceof ObjectNode o ? o : Json.object();
        if (status >= 400) {
            String error = Json.str(data, "error");
            String description = Json.str(data, "error_description");
            throw new TouchQueIdJagException(error != null ? error : "server_error", description != null ? description : url + " answered " + status, status);
        }
        return data;
    }

    /** Trades a member's ID token for an ID-JAG at the identity provider (token exchange, client_secret_basic). */
    public static IdJagGrant requestIdJag(RequestOptions o) {
        String endpoint = o.tokenEndpoint;
        if (endpoint == null || endpoint.isEmpty()) {
            if (o.issuer == null || o.issuer.isEmpty()) throw new TouchQueConfigException("requestIdJag needs issuer or tokenEndpoint");
            endpoint = Json.str(discover(o.issuer, CrossAppAccess::getJson), "token_endpoint");
            if (endpoint == null) throw new TouchQueConfigException("the identity provider names no token_endpoint");
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", TOKEN_EXCHANGE_GRANT);
        form.put("requested_token_type", ID_JAG_TOKEN_TYPE);
        form.put("subject_token", o.idToken);
        form.put("subject_token_type", ID_TOKEN_TYPE);
        form.put("audience", o.audience);
        form.put("resource", o.resource);
        form.put("scope", o.scope);
        ObjectNode data = postForm(endpoint, form, o.clientId, o.clientSecret);
        String assertion = Json.str(data, "access_token");
        if (!ID_JAG_TOKEN_TYPE.equals(Json.str(data, "issued_token_type")) || assertion == null || assertion.isEmpty()) {
            throw new TouchQueIdJagException("invalid_response", "the identity provider did not answer with an ID-JAG");
        }
        Long expiresIn = Json.lng(data, "expires_in");
        return new IdJagGrant(assertion, expiresIn == null ? null : expiresIn.intValue(), Json.str(data, "scope"));
    }

    /** Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer). */
    public static ObjectNode redeemIdJag(RedeemOptions o) {
        boolean isPublic = o.clientSecret == null || o.clientSecret.isEmpty();
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", JWT_BEARER_GRANT);
        form.put("assertion", o.assertion);
        form.put("resource", o.resource);
        form.put("scope", o.scope);
        form.put("client_id", isPublic ? o.clientId : null);
        return postForm(o.tokenEndpoint, form, isPublic ? null : o.clientId, isPublic ? null : o.clientSecret);
    }
}
