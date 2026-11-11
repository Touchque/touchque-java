package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.agents.SecurityEventVerifier;
import com.touchque.internal.Json;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/**
 * Shared Signals SETs: the cross-SDK vectors (fixtures/security-event-vectors.json), discovery
 * through /.well-known/ssf-configuration, and a poll (RFC 8936), the same cases as the Node SDK.
 */
class SecurityEventTest {
    private static final JsonNode V = Support.fixture("security-event-vectors.json");

    private static SecurityEventVerifier verifier() {
        return new SecurityEventVerifier(new SecurityEventVerifier.Options(V.get("issuer").asText(), V.get("audience").asText()).jwks(V.get("jwks")));
    }

    @Test
    void readsEveryValidVector() {
        for (JsonNode v : V.get("valid")) {
            SecurityEventVerifier.SecurityEvent e = verifier().verify(v.get("token").asText());
            ObjectNode got = Json.object();
            got.put("jti", e.jti());
            got.put("issuer", e.issuer());
            e.audience().forEach(got.putArray("audience")::add);
            got.put("issuedAt", e.issuedAt());
            got.put("txn", e.txn());
            got.set("subject", e.subject());
            got.put("type", e.type());
            got.put("name", e.name());
            got.set("claims", e.claims());
            assertEquals(v.get("expect"), Json.parse(Json.write(got)), v.get("name").asText());
        }
    }

    @Test
    void refusesEveryInvalidVector() {
        for (JsonNode v : V.get("invalid")) {
            TouchqueSecurityEventException e = assertThrows(TouchqueSecurityEventException.class, () -> verifier().verify(v.get("token").asText()), v.get("name").asText());
            assertEquals(v.get("error").asText(), e.error(), v.get("name").asText());
        }
    }

    @Test
    void shortNames() {
        assertTrue(SecurityEventVerifier.TYPES.get("session-revoked").endsWith("/caep/event-type/session-revoked"));
    }

    /** A transmitter on this machine: its metadata, its keys, and a poll endpoint that keeps what it was sent. */
    private static Support.Stub transmitter(AtomicReference<String> base, AtomicReference<Support.Seen> polled, String metadataIssuer) throws Exception {
        JsonNode first = V.get("valid").get(0);
        return new Support.Stub(seen -> {
            if (seen.path().equals("/.well-known/ssf-configuration")) {
                return Support.Answer.json(200, Map.of("issuer", metadataIssuer != null ? metadataIssuer : base.get(), "jwks_uri", base.get() + "/jwks"));
            }
            if (seen.path().equals("/jwks")) return Support.Answer.json(200, V.get("jwks"));
            if (seen.path().equals("/ssf/poll/denied")) return Support.Answer.json(401, Map.of("error", "authentication_failed"));
            polled.set(seen);
            return Support.Answer.json(200, Map.of("sets", Map.of(first.get("expect").get("jti").asText(), first.get("token").asText()), "moreAvailable", false));
        });
    }

    @Test
    void discoversTheJwksAndChecksTheIssuerTheSetNames() throws Exception {
        AtomicReference<String> base = new AtomicReference<>();
        AtomicReference<Support.Seen> polled = new AtomicReference<>();
        JsonNode first = V.get("valid").get(0);
        try (Support.Stub stub = transmitter(base, polled, null)) {
            base.set(stub.baseUrl);
            SecurityEventVerifier verifier = new SecurityEventVerifier(new SecurityEventVerifier.Options(stub.baseUrl, V.get("audience").asText()));
            // The vectors' issuer is not this one: the signature verifies, the issuer does not.
            assertEquals("invalid_issuer", assertThrows(TouchqueSecurityEventException.class, () -> verifier.verify(first.get("token").asText())).error());

            SecurityEventVerifier.PollResult out = SecurityEventVerifier.poll(new SecurityEventVerifier.PollOptions(stub.baseUrl + "/ssf/poll/s1", "tqssf_x")
                    .ack(List.of("a")).maxEvents(5));
            assertEquals(first.get("token").asText(), out.sets().get(first.get("expect").get("jti").asText()));
            assertFalse(out.moreAvailable());
            assertEquals(List.of("POST", "/ssf/poll/s1", "Bearer tqssf_x"), List.of(polled.get().method(), polled.get().path(), polled.get().header("Authorization")));
            assertEquals(Json.parse("{\"ack\":[\"a\"],\"maxEvents\":5}"), Json.parse(polled.get().body()));
        }
    }

    @Test
    void metadataForAnotherIssuerIsRefusedAndAFailedPollThrows() throws Exception {
        AtomicReference<String> base = new AtomicReference<>();
        AtomicReference<Support.Seen> polled = new AtomicReference<>();
        try (Support.Stub stub = transmitter(base, polled, "https://elsewhere.example")) {
            base.set(stub.baseUrl);
            SecurityEventVerifier verifier = new SecurityEventVerifier(new SecurityEventVerifier.Options(stub.baseUrl, V.get("audience").asText()));
            // Keys that cannot be read are the transmitter's problem: answer 503 and it tries again.
            assertEquals("temporarily_unavailable",
                    assertThrows(TouchqueSecurityEventException.class, () -> verifier.verify(V.get("valid").get(0).get("token").asText())).error());

            TouchqueSecurityEventException denied = assertThrows(TouchqueSecurityEventException.class,
                    () -> SecurityEventVerifier.poll(new SecurityEventVerifier.PollOptions(stub.baseUrl + "/ssf/poll/denied", "tqssf_x")));
            assertEquals("authentication_failed", denied.error());
        }
        assertThrows(TouchqueConfigException.class, () -> SecurityEventVerifier.poll(new SecurityEventVerifier.PollOptions("http://transmitter.example/poll", "tqssf_x")));
        assertThrows(TouchqueConfigException.class, () -> SecurityEventVerifier.poll(new SecurityEventVerifier.PollOptions("https://transmitter.example/poll", "")));
    }
}
