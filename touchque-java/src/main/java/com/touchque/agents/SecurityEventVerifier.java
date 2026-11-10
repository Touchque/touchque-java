package com.touchque.agents;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchQueConfigException;
import com.touchque.TouchQueSecurityEventException;
import com.touchque.crypto.Jws;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shared Signals (OpenID Shared Signals Framework 1.0): Security Event Tokens (SETs, RFC 8417) an
 * identity provider sends when something happens to a person's account after sign-in: CAEP
 * session-revoked, credential-change, device-compliance-change; RISC account-disabled,
 * credential-compromise. TouchQue SSO sends them for an organization's members to the receivers
 * its admin adds (Organization &gt; Continuous access). Your app ends the person's sessions or asks
 * them to sign in again.
 *
 * <p>Push delivery (RFC 8935), the SET is the request body (application/secevent+jwt):
 *
 * <pre>{@code
 * var verifier = new SecurityEventVerifier(new SecurityEventVerifier.Options("https://sso.touchque.com", "https://app.example.com"));
 * @PostMapping(value = "/ssf", consumes = "application/secevent+jwt")
 * ResponseEntity<?> ssf(@RequestBody String body) {
 *     try {
 *         var event = verifier.verify(body);
 *         if ("session-revoked".equals(event.name())) endSessionsOf(event.subject().path("email").asText());
 *         return ResponseEntity.accepted().build();
 *     } catch (TouchQueSecurityEventException e) {
 *         return ResponseEntity.badRequest().body(Map.of("err", e.error(), "description", e.getMessage()));
 *     }
 * }
 * }</pre>
 *
 * <p>Poll delivery (RFC 8936): {@link #poll(PollOptions)}. A SET does not expire: it says what
 * happened. Keep the jtis you handled and skip a repeat.
 */
public final class SecurityEventVerifier {
    /** The event types TouchQue sends, by their short name. */
    public static final Map<String, String> TYPES;

    static {
        Map<String, String> t = new LinkedHashMap<>();
        t.put("session-revoked", "https://schemas.openid.net/secevent/caep/event-type/session-revoked");
        t.put("credential-change", "https://schemas.openid.net/secevent/caep/event-type/credential-change");
        t.put("device-compliance-change", "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change");
        t.put("account-disabled", "https://schemas.openid.net/secevent/risc/event-type/account-disabled");
        t.put("credential-compromise", "https://schemas.openid.net/secevent/risc/event-type/credential-compromise");
        t.put("verification", "https://schemas.openid.net/secevent/ssf/event-type/verification");
        t.put("stream-updated", "https://schemas.openid.net/secevent/ssf/event-type/stream-updated");
        TYPES = Collections.unmodifiableMap(t);
    }

    private static final Pattern NAMESPACE = Pattern.compile("^https://schemas\\.openid\\.net/secevent/(caep|risc|ssf)/event-type/([a-z0-9-]+)$");
    private static final HttpClient POLL_CLIENT = TouchQueHttp.createClient(Duration.ofSeconds(30));

    private final String issuer;
    private final String audience;
    private final long skew;
    private final boolean pinned;
    private final Function<String, JsonNode> fetch;
    private final Object keysLock = new Object();
    private Map<String, JsonNode> keys = new HashMap<>();
    private String jwksUri;
    private Instant keysAt;
    private Instant triedAt = Instant.EPOCH;

    /** Settings of {@link SecurityEventVerifier}. */
    public static final class Options {
        private final String issuer;
        private final String audience;
        private String jwksUri;
        private JsonNode jwks;
        private Duration clockSkew = Duration.ofSeconds(300);
        private Function<String, JsonNode> fetch;

        /**
         * @param issuer the transmitter's issuer, e.g. https://sso.touchque.com.
         * @param audience your stream's audience (aud), as the dashboard shows it.
         */
        public Options(String issuer, String audience) {
            this.issuer = issuer;
            this.audience = audience;
        }

        /** Its JWKS, when not found from the issuer's /.well-known/ssf-configuration. */
        public Options jwksUri(String v) {
            this.jwksUri = v;
            return this;
        }

        /** Fixed keys instead (tests, or keys you pin): {@code {"keys": [...]}}. */
        public Options jwks(JsonNode v) {
            this.jwks = v;
            return this;
        }

        public Options clockSkew(Duration v) {
            this.clockSkew = v;
            return this;
        }

        /** For tests: how JSON documents are fetched. */
        public Options fetch(Function<String, JsonNode> v) {
            this.fetch = v;
            return this;
        }
    }

    /**
     * A verified SET. {@code txn}: the case code of TouchQue's decision ("Why?" in the dashboard), or
     * null; {@code subject}: sub_id as sent; {@code type}: the event type URI; {@code name}: its short
     * name (session-revoked …) for CAEP, RISC and SSF types, null for others; {@code claims}: the
     * event's own (event_timestamp, reason_admin, credential_type …).
     */
    public record SecurityEvent(String jti, String issuer, List<String> audience, long issuedAt, String txn, ObjectNode subject, String type,
            String name, ObjectNode claims) {
    }

    public SecurityEventVerifier(Options options) {
        if (options.issuer == null || options.issuer.isEmpty() || options.audience == null || options.audience.isEmpty()) {
            throw new TouchQueConfigException("SecurityEventVerifier needs issuer (the transmitter) and audience (your stream's aud)");
        }
        this.issuer = options.issuer;
        this.audience = options.audience;
        this.jwksUri = options.jwksUri;
        this.skew = options.clockSkew != null ? options.clockSkew.getSeconds() : 300;
        this.fetch = options.fetch != null ? options.fetch : CrossAppAccess::getJson;
        this.pinned = options.jwks != null;
        if (pinned) setKeys(options.jwks);
    }

    private void setKeys(JsonNode jwks) {
        Map<String, JsonNode> loaded = new HashMap<>();
        JsonNode list = jwks.get("keys");
        if (list != null && list.isArray()) {
            for (JsonNode k : list) {
                String kid = Json.str(k, "kid");
                if (k.isObject() && kid != null && !kid.isEmpty()) loaded.put(kid, k);
            }
        }
        keys = loaded;
        keysAt = Instant.now();
    }

    private void loadKeys() {
        if (jwksUri == null || jwksUri.isEmpty()) {
            JsonNode meta = fetch.apply(issuer.replaceAll("/+$", "") + "/.well-known/ssf-configuration");
            String uri = Json.str(meta, "jwks_uri");
            if (!issuer.equals(Json.str(meta, "issuer")) || uri == null) throw new IllegalStateException("the transmitter's metadata does not match its issuer");
            jwksUri = uri;
        }
        if (!CrossAppAccess.safeUrl(jwksUri)) throw new IllegalStateException(jwksUri + " must be an https URL");
        setKeys(fetch.apply(jwksUri));
    }

    private JsonNode keyFor(String kid) {
        synchronized (keysLock) {
            if (pinned) return keys.get(kid);
            if (keysAt == null || Duration.between(keysAt, Instant.now()).toMinutes() >= 60) loadKeys();
            if (!keys.containsKey(kid) && Duration.between(triedAt, Instant.now()).toSeconds() > 300) {
                triedAt = Instant.now();
                loadKeys();
            }
            return keys.get(kid);
        }
    }

    private static TouchQueSecurityEventException bad(String message) {
        return new TouchQueSecurityEventException("invalid_request", message);
    }

    /** The SET, checked (signature RS256 with the issuer's keys, typ, issuer, audience, one event); throws {@link TouchQueSecurityEventException}. */
    public SecurityEvent verify(String token) {
        Jws.Parts parts = Jws.split(token != null ? token.trim() : "");
        if (parts == null) throw bad("not a JWT");
        ObjectNode head = parts.header();
        ObjectNode c = parts.claims();
        String typ = Json.str(head, "typ");
        if (typ == null || !typ.equalsIgnoreCase("secevent+jwt")) throw bad("not a Security Event Token (typ secevent+jwt)");
        String kid = Json.str(head, "kid");
        if (!"RS256".equals(Json.str(head, "alg")) || kid == null) throw new TouchQueSecurityEventException("invalid_key", "unsupported signature");
        JsonNode jwk;
        try {
            jwk = keyFor(kid);
        } catch (RuntimeException e) {
            throw new TouchQueSecurityEventException("temporarily_unavailable", "the transmitter's keys could not be read: " + e.getMessage());
        }
        if (jwk == null || !Jws.verify("RS256", jwk, parts.input(), parts.signature())) {
            throw new TouchQueSecurityEventException("invalid_key", "signature does not verify");
        }
        if (!issuer.equals(Json.str(c, "iss"))) throw new TouchQueSecurityEventException("invalid_issuer", "another issuer");
        List<String> aud = new ArrayList<>();
        JsonNode a = c.get("aud");
        if (a != null && a.isArray()) {
            for (JsonNode x : a) if (x.isTextual()) aud.add(x.asText());
        } else if (a != null && a.isTextual()) {
            aud.add(a.asText());
        }
        if (!aud.contains(audience)) throw new TouchQueSecurityEventException("invalid_audience", "not for this receiver");
        String jti = Json.str(c, "jti");
        JsonNode iat = c.get("iat");
        if (jti == null || iat == null || !iat.isIntegralNumber()) throw bad("jti and iat are required");
        if (iat.asLong() - skew > Instant.now().getEpochSecond()) throw bad("issued in the future");
        JsonNode events = c.get("events");
        if (events == null || !events.isObject() || events.size() != 1) throw bad("a SET carries exactly one event");
        Map.Entry<String, JsonNode> event = events.fields().next();
        Matcher m = NAMESPACE.matcher(event.getKey());
        JsonNode sub = c.get("sub_id");
        return new SecurityEvent(jti, issuer, List.copyOf(aud), iat.asLong(), Json.str(c, "txn"),
                sub instanceof ObjectNode o ? o : Json.object(), event.getKey(), m.matches() ? m.group(2) : null,
                event.getValue() instanceof ObjectNode o ? o : Json.object());
    }

    /** One poll (RFC 8936). */
    public static final class PollOptions {
        private final String url;
        private final String token;
        private List<String> ack;
        private ObjectNode setErrs;
        private Integer maxEvents;
        private Boolean returnImmediately;

        /**
         * @param url the stream's poll endpoint (its delivery.endpoint_url).
         * @param token the stream's token.
         */
        public PollOptions(String url, String token) {
            this.url = url;
            this.token = token;
        }

        /** jtis you handled since the last poll. */
        public PollOptions ack(List<String> v) {
            this.ack = v;
            return this;
        }

        /** jtis you could not handle: {@code {jti: {"err": ..., "description": ...}}}. */
        public PollOptions setErrs(ObjectNode v) {
            this.setErrs = v;
            return this;
        }

        public PollOptions maxEvents(int v) {
            this.maxEvents = v;
            return this;
        }

        public PollOptions returnImmediately(boolean v) {
            this.returnImmediately = v;
            return this;
        }
    }

    /** The waiting SETs (jti to token) and whether more wait. */
    public record PollResult(Map<String, String> sets, boolean moreAvailable) {
    }

    /** Acknowledges what you handled and returns the waiting SETs. */
    public static PollResult poll(PollOptions o) {
        if (!CrossAppAccess.safeUrl(o.url)) throw new TouchQueConfigException(o.url + " must be an https URL");
        if (o.token == null || o.token.isEmpty()) throw new TouchQueConfigException("poll needs the stream's token");
        ObjectNode body = Json.object();
        if (o.ack != null) {
            ArrayNode list = body.putArray("ack");
            o.ack.forEach(list::add);
        }
        if (o.setErrs != null) body.set("setErrs", o.setErrs);
        if (o.maxEvents != null) body.put("maxEvents", o.maxEvents);
        if (o.returnImmediately != null) body.put("returnImmediately", o.returnImmediately);
        try {
            HttpResponse<InputStream> res = POLL_CLIENT.send(HttpRequest.newBuilder(URI.create(o.url)).timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/json").header("Accept", "application/json").header("Authorization", "Bearer " + o.token)
                    .POST(HttpRequest.BodyPublishers.ofString(Json.write(body))).build(), HttpResponse.BodyHandlers.ofInputStream());
            ObjectNode data = Json.parseObject(TouchQueHttp.readLimited(res.body()));
            if (res.statusCode() != 200) {
                String err = Json.str(data, "error");
                throw new TouchQueSecurityEventException(err != null ? err : "server_error", o.url + " answered " + res.statusCode());
            }
            Map<String, String> sets = new LinkedHashMap<>();
            JsonNode s = data.get("sets");
            if (s != null && s.isObject()) s.fields().forEachRemaining(e -> {
                if (e.getValue().isTextual()) sets.put(e.getKey(), e.getValue().asText());
            });
            return new PollResult(sets, Json.bool(data, "moreAvailable"));
        } catch (IOException e) {
            throw new IllegalStateException(e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }
}
