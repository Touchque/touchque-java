package com.touchque.agents;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueConfigException;
import com.touchque.TouchqueMcpAuthException;
import com.touchque.crypto.AgentKeys;
import com.touchque.crypto.Jws;
import com.touchque.internal.Json;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * For an MCP server whose authorization server is Touchque SSO (Organization → MCP servers in
 * the dashboard):
 * <ul>
 * <li>{@link #protectedResourceMetadata()} is its RFC 9728 document, served at
 * {@link #metadataPaths()}, so MCP clients find Touchque and ask for a token for exactly this server;</li>
 * <li>{@link #verify} checks a request's token: signed by Touchque, this issuer, audience = this
 * server, not expired, and for a DPoP-bound token a fresh proof for this request.
 * {@link TouchqueMcpAuthException} carries the status and the WWW-Authenticate header to send;</li>
 * <li>{@link #requireTool} refuses with 403 insufficient_scope naming the scope a tool needs.</li>
 * </ul>
 */
public final class McpAuth {
    private final String issuer;
    private final String resource;
    private final Map<String, String> tools;
    private final String resourceName;
    private final long skew;
    private final Function<String, JsonNode> fetch;
    private final Object keysLock = new Object();
    private final Map<String, Long> proofs = new ConcurrentHashMap<>();
    private Map<String, JsonNode> keys = new HashMap<>();
    private Instant keysAt;
    private Instant triedAt = Instant.EPOCH;

    /** Settings of {@link McpAuth}. */
    public static final class Options {
        private final String issuer;
        private final String resource;
        private Map<String, String> tools;
        private String resourceName;
        private Duration clockSkew = Duration.ofSeconds(60);
        private Function<String, JsonNode> fetch;

        /**
         * @param issuer Touchque SSO's MCP issuer, e.g. https://sso.touchque.com/mcp.
         * @param resource this MCP server's URL (the audience of its tokens, RFC 8707).
         */
        public Options(String issuer, String resource) {
            this.issuer = issuer;
            this.resource = resource;
        }

        /** Tool name → the scope it needs. */
        public Options tools(Map<String, String> v) {
            this.tools = v;
            return this;
        }

        public Options resourceName(String v) {
            this.resourceName = v;
            return this;
        }

        /** Allowed clock skew (default 60 seconds). */
        public Options clockSkew(Duration v) {
            this.clockSkew = v;
            return this;
        }

        /** For tests: how JSON documents are fetched (default: a GET that never follows redirects). */
        public Options fetch(Function<String, JsonNode> v) {
            this.fetch = v;
            return this;
        }
    }

    /** A request's checked token. */
    public record Claims(String sub, String email, String clientId, List<String> scopes, String orgId, long expiresAt, boolean dpopBound, ObjectNode claims) {
    }

    public McpAuth(Options options) {
        if (options.issuer == null || options.issuer.isEmpty() || options.resource == null || options.resource.isEmpty()) {
            throw new TouchqueConfigException("McpAuth needs issuer (Touchque SSO's MCP issuer) and resource (this server's URL)");
        }
        this.issuer = options.issuer.replaceAll("/+$", "");
        this.resource = options.resource;
        this.tools = options.tools != null ? Map.copyOf(options.tools) : Map.of();
        this.resourceName = options.resourceName;
        this.skew = options.clockSkew != null ? options.clockSkew.getSeconds() : 60;
        this.fetch = options.fetch != null ? options.fetch : CrossAppAccess::getJson;
    }

    /** Where to serve {@link #protectedResourceMetadata()}. */
    public List<String> metadataPaths() {
        String path = pathOf(resource).replaceAll("/+$", "");
        return path.isEmpty()
                ? List.of("/.well-known/oauth-protected-resource")
                : List.of("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource" + path);
    }

    public String metadataUrl() {
        List<String> paths = metadataPaths();
        return origin(resource) + paths.get(paths.size() - 1);
    }

    /** The RFC 9728 protected resource metadata of this server. */
    public ObjectNode protectedResourceMetadata() {
        ObjectNode doc = Json.object().put("resource", resource);
        doc.set("authorization_servers", Json.array().add(issuer));
        doc.set("bearer_methods_supported", Json.array().add("header"));
        ArrayNode scopes = Json.array();
        new LinkedHashSet<>(tools.values()).forEach(scopes::add);
        doc.set("scopes_supported", scopes);
        doc.set("dpop_signing_alg_values_supported", Json.array().add("ES256").add("EdDSA"));
        if (resourceName != null) doc.put("resource_name", resourceName);
        return doc;
    }

    /**
     * A request's token, checked.
     *
     * @param header a case-insensitive header getter (e.g. {@code request::getHeader}).
     */
    public Claims verify(String method, String url, Function<String, String> header) {
        String auth = header.apply("authorization");
        auth = auth == null ? "" : auth.trim();
        int space = auth.indexOf(' ');
        String scheme = (space < 0 ? auth : auth.substring(0, space)).toLowerCase(Locale.ROOT);
        String token = space < 0 ? "" : auth.substring(space + 1).trim();
        if (!(scheme.equals("bearer") || scheme.equals("dpop")) || token.chars().filter(c -> c == '.').count() != 2) {
            throw fail(401, "missing_token", "A Touchque access token is required", null);
        }
        ObjectNode claims = claims(token);
        String jkt = Json.str(claims.get("cnf"), "jkt");
        boolean bound = jkt != null && !jkt.isEmpty();
        if (bound) {
            if (!scheme.equals("dpop")) throw fail(401, "invalid_token", "This token is bound to a DPoP key: send it as DPoP with a proof", null);
            checkProof(header.apply("dpop"), method, url, token, jkt);
        }
        String scope = Json.str(claims, "scope");
        List<String> scopes = scope == null || scope.isBlank() ? List.of() : List.of(scope.trim().split("\\s+"));
        Long exp = Json.lng(claims, "exp");
        return new Claims(orEmpty(Json.str(claims, "sub")), Json.str(claims, "email"), orEmpty(Json.str(claims, "client_id")), scopes,
                Json.str(claims, "org_id"), exp != null ? exp : 0, bound, claims);
    }

    /** Checks a request's token from a header map (any key case). */
    public Claims verify(String method, String url, Map<String, String> headers) {
        Map<String, String> lower = new HashMap<>();
        headers.forEach((k, v) -> lower.put(k.toLowerCase(Locale.ROOT), v));
        return verify(method, url, name -> lower.get(name.toLowerCase(Locale.ROOT)));
    }

    public void requireScope(Claims claims, String scope) {
        if (!claims.scopes().contains(scope)) throw fail(403, "insufficient_scope", "This needs the " + scope + " scope", scope);
    }

    public void requireTool(Claims claims, String tool) {
        String scope = tools.get(tool);
        if (scope == null || scope.isEmpty()) throw fail(403, "insufficient_scope", "No scope is set for the tool " + tool, null);
        requireScope(claims, scope);
    }

    private TouchqueMcpAuthException fail(int status, String code, String message, String scope) {
        List<String> parts = new ArrayList<>();
        parts.add("resource_metadata=\"" + metadataUrl() + "\"");
        if (!code.equals("missing_token")) {
            parts.add("error=\"" + code + "\"");
            parts.add("error_description=\"" + message.replace('"', '\'') + "\"");
            if (scope != null) parts.add("scope=\"" + scope + "\"");
        }
        return new TouchqueMcpAuthException(status, code, message, "Bearer " + String.join(", ", parts));
    }

    private ObjectNode claims(String token) {
        Jws.Parts parts = Jws.split(token);
        if (parts == null) throw fail(401, "invalid_token", "The token is malformed", null);
        String alg = Json.str(parts.header(), "alg");
        if (!"at+jwt".equals(Json.str(parts.header(), "typ")) || !("RS256".equals(alg) || "ES256".equals(alg))) {
            throw fail(401, "invalid_token", "Not a Touchque access token", null);
        }
        JsonNode key;
        try {
            key = keyFor(orEmpty(Json.str(parts.header(), "kid")));
        } catch (TouchqueMcpAuthException e) {
            throw e;
        } catch (RuntimeException e) {
            throw fail(401, "invalid_token", "The authorization server's keys could not be read", null);
        }
        if (key == null || !Jws.verify(alg, key, parts.input(), parts.signature())) throw fail(401, "invalid_token", "The token signature does not verify", null);
        ObjectNode claims = parts.claims();
        if (!orEmpty(Json.str(claims, "iss")).replaceAll("/+$", "").equals(issuer)) throw fail(401, "invalid_token", "The token is from another issuer", null);
        JsonNode aud = claims.get("aud");
        boolean forUs = false;
        if (aud != null && aud.isArray()) {
            for (JsonNode a : aud) forUs |= a.isTextual() && a.asText().equals(resource);
        } else {
            forUs = resource.equals(Json.str(claims, "aud"));
        }
        if (!forUs) throw fail(401, "invalid_token", "The token is for another server", null);
        Long exp = Json.lng(claims, "exp");
        if (exp == null || exp + skew <= Instant.now().getEpochSecond()) throw fail(401, "invalid_token", "The token expired", null);
        return claims;
    }

    private void loadKeys() {
        JsonNode meta = fetch.apply(origin(issuer) + "/.well-known/oauth-authorization-server" + pathOf(issuer).replaceAll("/+$", ""));
        String jwksUri = Json.str(meta, "jwks_uri");
        if (!orEmpty(Json.str(meta, "issuer")).replaceAll("/+$", "").equals(issuer) || jwksUri == null || jwksUri.isEmpty()) {
            throw new IllegalStateException("the authorization server metadata does not match the issuer");
        }
        Map<String, JsonNode> loaded = new HashMap<>();
        JsonNode list = fetch.apply(jwksUri).get("keys");
        if (list != null && list.isArray()) {
            for (JsonNode k : list) {
                String kid = Json.str(k, "kid");
                if (k.isObject() && kid != null && !kid.isEmpty()) loaded.put(kid, k);
            }
        }
        keys = loaded;
        keysAt = Instant.now();
    }

    private JsonNode keyFor(String kid) {
        synchronized (keysLock) {
            if (keysAt == null || Duration.between(keysAt, Instant.now()).toMinutes() >= 10) loadKeys();
            if (!keys.containsKey(kid) && Duration.between(triedAt, Instant.now()).toSeconds() > 60) {
                triedAt = Instant.now();
                loadKeys();
            }
            return keys.get(kid);
        }
    }

    private void checkProof(String proof, String method, String url, String token, String jkt) {
        if (proof == null || proof.isEmpty() || proof.chars().filter(c -> c == '.').count() != 2) throw reject("missing");
        Jws.Parts parts = Jws.split(proof);
        if (parts == null) throw reject("malformed");
        JsonNode jwk = parts.header().get("jwk");
        String kty = Json.str(jwk, "kty");
        if (!"dpop+jwt".equals(Json.str(parts.header(), "typ")) || jwk == null || !jwk.isObject() || jwk.has("d")
                || !("EC".equals(kty) || "OKP".equals(kty)) || !AgentKeys.thumbprint(jwk).equals(jkt)) {
            throw reject("not the bound key");
        }
        if (!Jws.verify(orEmpty(Json.str(parts.header(), "alg")), jwk, parts.input(), parts.signature())) throw reject("signature");
        ObjectNode claims = parts.claims();
        String htu = url.split("[?#]", 2)[0];
        if (!method.toUpperCase(Locale.ROOT).equals(Json.str(claims, "htm")) || !htu.equals(Json.str(claims, "htu"))) throw reject("htm/htu");
        long now = Instant.now().getEpochSecond();
        Long iat = Json.lng(claims, "iat");
        if (Math.abs((iat != null ? iat : 0) - now) > skew) throw reject("iat");
        if (!AgentKeys.accessTokenHash(token).equals(Json.str(claims, "ath"))) throw reject("ath");
        proofs.entrySet().removeIf(e -> e.getValue() < now);
        String jti = orEmpty(Json.str(claims, "jti"));
        if (jti.isEmpty() || proofs.putIfAbsent(jti, now + 2 * skew) != null) throw reject("jti used");
    }

    private TouchqueMcpAuthException reject(String why) {
        return fail(401, "invalid_dpop_proof", "DPoP proof: " + why, null);
    }

    static String origin(String url) {
        URI u = URI.create(url);
        return u.getScheme() + "://" + u.getRawAuthority();
    }

    static String pathOf(String url) {
        String p = URI.create(url).getRawPath();
        return p == null ? "" : p;
    }

    private static String orEmpty(String s) {
        return s != null ? s : "";
    }
}
