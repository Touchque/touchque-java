package com.touchque.agents;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchQueConfigException;
import com.touchque.TouchQueIdJagException;
import com.touchque.crypto.Jws;
import com.touchque.internal.Json;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiPredicate;
import java.util.function.Function;

/**
 * Your authorization server, taking ID-JAGs from an organization's identity provider: checks the
 * one an authenticated client presents (jwt-bearer grant) and uses it once.
 *
 * <pre>{@code
 * var verifier = new IdJagVerifier(new IdJagVerifier.Options("https://sso.touchque.com", "https://auth.files.example"));
 * var claims = verifier.verify(form.get("assertion"), authenticatedClientId);
 * }</pre>
 */
public final class IdJagVerifier {
    private final String issuer;
    private final String audience;
    private final long skew;
    private final BiPredicate<String, Long> firstUse;
    private final Function<String, JsonNode> fetch;
    private final Object keysLock = new Object();
    private final Map<String, Long> seen = new ConcurrentHashMap<>();
    private Map<String, JsonNode> keys = new HashMap<>();
    private String jwksUri;
    private Instant keysAt;
    private Instant triedAt = Instant.EPOCH;

    /** Settings of {@link IdJagVerifier}. */
    public static final class Options {
        private final String issuer;
        private final String audience;
        private String jwksUri;
        private Duration clockSkew = Duration.ofSeconds(60);
        private BiPredicate<String, Long> firstUse;
        private Function<String, JsonNode> fetch;

        /**
         * @param issuer the identity provider, e.g. https://sso.touchque.com.
         * @param audience your authorization server's issuer identifier (the ID-JAG's aud).
         */
        public Options(String issuer, String audience) {
            this.issuer = issuer;
            this.audience = audience;
        }

        /** Its JWKS, when not found from the issuer's /.well-known/openid-configuration. */
        public Options jwksUri(String v) {
            this.jwksUri = v;
            return this;
        }

        public Options clockSkew(Duration v) {
            this.clockSkew = v;
            return this;
        }

        /**
         * Records an ID-JAG's jti (with its exp) and says whether it is new (each is used once).
         * Defaults to memory in this process; give a shared store (Redis SET NX) when several
         * processes take ID-JAGs.
         */
        public Options firstUse(BiPredicate<String, Long> v) {
            this.firstUse = v;
            return this;
        }

        /** For tests: how JSON documents are fetched. */
        public Options fetch(Function<String, JsonNode> v) {
            this.fetch = v;
            return this;
        }
    }

    /** A checked ID-JAG. {@code sub}: the member at the identity provider; {@code clientId}: your client_id of the app that presented it. */
    public record Claims(String iss, String sub, String aud, String clientId, String jti, long issuedAt, long expiresAt, List<String> scopes,
            String resource, String tenant, String email, Long authTime, List<String> amr, ObjectNode claims) {
    }

    public IdJagVerifier(Options options) {
        if (options.issuer == null || options.issuer.isEmpty() || options.audience == null || options.audience.isEmpty()) {
            throw new TouchQueConfigException("IdJagVerifier needs issuer (the identity provider) and audience (your authorization server's issuer)");
        }
        this.issuer = options.issuer;
        this.audience = options.audience;
        this.jwksUri = options.jwksUri;
        this.skew = options.clockSkew != null ? options.clockSkew.getSeconds() : 60;
        this.firstUse = options.firstUse != null ? options.firstUse : this::rememberOnce;
        this.fetch = options.fetch != null ? options.fetch : CrossAppAccess::getJson;
    }

    private boolean rememberOnce(String jti, Long exp) {
        long now = Instant.now().getEpochSecond();
        seen.entrySet().removeIf(e -> e.getValue() < now);
        return seen.putIfAbsent(jti, exp + skew) == null;
    }

    private void loadKeys() {
        if (jwksUri == null || jwksUri.isEmpty()) {
            jwksUri = Json.str(CrossAppAccess.discover(issuer, fetch), "jwks_uri");
            if (jwksUri == null) throw new IllegalStateException("the identity provider names no jwks_uri");
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

    private static TouchQueIdJagException bad(String message) {
        return new TouchQueIdJagException("invalid_grant", message);
    }

    /** The ID-JAG, checked and used once; throws {@link TouchQueIdJagException} (error invalid_grant). */
    public Claims verify(String assertion, String clientId) {
        Jws.Parts parts = Jws.split(assertion != null ? assertion : "");
        if (parts == null) throw bad("assertion is not a JWT");
        ObjectNode head = parts.header();
        ObjectNode c = parts.claims();
        if (!"oauth-id-jag+jwt".equals(Json.str(head, "typ"))) throw bad("not an ID-JAG (typ oauth-id-jag+jwt)");
        String alg = Json.str(head, "alg");
        String kid = Json.str(head, "kid");
        if (!("RS256".equals(alg) || "ES256".equals(alg) || "EdDSA".equals(alg)) || kid == null || kid.isEmpty()) throw bad("unsupported signature");
        JsonNode key;
        try {
            key = keyFor(kid);
        } catch (RuntimeException e) {
            throw new TouchQueIdJagException("temporarily_unavailable", "the identity provider's keys could not be read: " + e.getMessage());
        }
        if (key == null || !Jws.verify(alg, key, parts.input(), parts.signature())) throw bad("signature does not verify");
        long now = Instant.now().getEpochSecond();
        List<String> auds = new ArrayList<>();
        JsonNode aud = c.get("aud");
        if (aud != null && aud.isArray()) aud.forEach(a -> auds.add(a.isTextual() ? a.asText() : null));
        else auds.add(Json.str(c, "aud"));
        Long exp = Json.lng(c, "exp");
        Long iat = Json.lng(c, "iat");
        String sub = Json.str(c, "sub");
        String jti = Json.str(c, "jti");
        if (!issuer.equals(Json.str(c, "iss"))) throw bad("another issuer");
        if (auds.size() != 1 || !audience.equals(auds.get(0))) throw bad("not for this authorization server");
        if (clientId == null || clientId.isEmpty() || !clientId.equals(Json.str(c, "client_id"))) throw bad("issued to another client");
        if (exp == null || exp + skew < now) throw bad("expired");
        if (iat == null || iat - skew > now) throw bad("issued in the future");
        if (sub == null || sub.isEmpty() || jti == null || jti.isEmpty()) throw bad("sub and jti are required");
        if (!firstUse.test(jti, exp)) throw bad("already used");
        String scope = Json.str(c, "scope");
        List<String> amr = new ArrayList<>();
        if (c.get("amr") != null && c.get("amr").isArray()) c.get("amr").forEach(a -> amr.add(a.asText()));
        return new Claims(issuer, sub, audience, clientId, jti, iat, exp, scope == null || scope.isEmpty() ? List.of() : List.of(scope.split(" ")),
                Json.str(c, "resource"), Json.str(c, "tenant"), Json.str(c, "email"), Json.lng(c, "auth_time"), List.copyOf(amr), c);
    }
}
