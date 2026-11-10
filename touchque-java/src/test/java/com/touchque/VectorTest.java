package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.crypto.AgentKeys;
import com.touchque.crypto.ApprovalProof;
import com.touchque.crypto.ApprovalToken;
import com.touchque.crypto.Details;
import com.touchque.flow.Steps;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;
import com.touchque.resources.Risk;
import com.touchque.resources.Webhook;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The cross-language fixtures (fixtures/): every SDK signs, canonicalizes, verifies and
 * matches exactly like the server and the other SDKs.
 */
class VectorTest {
    @Test
    void signatureVectors() {
        ObjectNode fx = Support.fixture("signature-vectors.json");
        assertFalse(fx.get("vectors").isEmpty());
        for (JsonNode v : fx.get("vectors")) {
            String sig = TouchQueHttp.sign(fx.get("secret").asText(), v.get("method").asText(), v.get("signed_path").asText(), v.get("body").asText(),
                    v.get("timestamp").asText(), v.get("nonce").asText());
            assertEquals(v.get("expected_signature").asText(), sig);
        }
    }

    @Test
    void webhookVectors() {
        ObjectNode fx = Support.fixture("webhook-vectors.json");
        Webhook webhook = new TouchQueClient(new TouchQueOptions().apiKey("tq_x").apiSecret(fx.get("secret").asText())).webhook();
        for (JsonNode v : fx.get("vectors")) {
            String body = v.get("delivered_body").asText();
            assertEquals(v.get("expected_canonical").asText(), Webhook.canonicalize(body));
            // The fixtures carry a fixed past timestamp: no freshness check.
            ObjectNode payload = webhook.verify(body, null, 0);
            assertEquals(Json.str(v.get("payload"), "requestId"), Json.str(payload, "requestId"));
        }
    }

    private static String signed(String secret, ObjectNode payload) {
        payload.put("signature", Crypto.hmacHex(secret, Webhook.canonicalize(Json.write(payload))));
        return Json.write(payload);
    }

    @Test
    void webhookSignatureTimestampAndReplay() {
        String secret = "whsec_test";
        Webhook webhook = new TouchQueClient(new TouchQueOptions().apiKey("tq_x").apiSecret(secret)).webhook();
        String now = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC).format(Instant.now());
        String fresh = signed(secret, Json.object().put("status", "SUCCESS").put("requestId", "r1").put("timestamp", now).put("jti", "j1").put("note", "Zoë Ångström / €"));
        Webhook.MemoryReplayCache cache = new Webhook.MemoryReplayCache();
        assertEquals("r1", Json.str(webhook.verify(fresh, null, 300, cache), "requestId"));
        TouchQueWebhookReplayException replay = assertThrows(TouchQueWebhookReplayException.class, () -> webhook.verify(fresh, null, 300, cache));
        assertEquals("j1", replay.jti());

        String old = signed(secret, Json.object().put("status", "SUCCESS").put("timestamp", "2020-01-01T00:00:00.000Z"));
        assertThrows(TouchQueWebhookSignatureException.class, () -> webhook.verify(old, null));
        String tampered = fresh.replace("\"r1\"", "\"r2\"");
        TouchQueWebhookSignatureException e = assertThrows(TouchQueWebhookSignatureException.class, () -> webhook.verify(tampered, null));
        assertFalse(e.getMessage().toLowerCase().contains("expected"));
        assertThrows(TouchQueWebhookSignatureException.class, () -> webhook.verify("not json", null));
        assertThrows(TouchQueWebhookSignatureException.class, () -> webhook.verify(signed(secret, Json.object().put("status", "SUCCESS")), null));
    }

    @Test
    void recoveryAndHelpDeskEventsAreTheNamesTheApiSends() {
        // The API's x-callback-event values (openapi: RecoveryEventWebhookPayload.event, the assist events).
        assertEquals(List.of("RECOVERY_STARTED", "RECOVERY_DEVICE_BOUND", "RECOVERY_COOLING", "RECOVERY_COMPLETED", "RECOVERY_VETOED", "RECOVERY_EXPIRED", "RECOVERY_FAILED"),
                List.of(Webhook.EVENT_RECOVERY_STARTED, Webhook.EVENT_RECOVERY_DEVICE_BOUND, Webhook.EVENT_RECOVERY_COOLING, Webhook.EVENT_RECOVERY_COMPLETED,
                        Webhook.EVENT_RECOVERY_VETOED, Webhook.EVENT_RECOVERY_EXPIRED, Webhook.EVENT_RECOVERY_FAILED));
        assertEquals(List.of("ASSIST_OPENED", "ASSIST_ENDED", "ASSIST_CHECK_PASSED", "ASSIST_CHECK_FAILED", "ASSIST_UNFROZEN", "ASSIST_CLAIM_CONFIRMED", "ASSIST_CLAIM_UNVERIFIED"),
                List.of(Webhook.EVENT_ASSIST_OPENED, Webhook.EVENT_ASSIST_ENDED, Webhook.EVENT_ASSIST_CHECK_PASSED, Webhook.EVENT_ASSIST_CHECK_FAILED,
                        Webhook.EVENT_ASSIST_UNFROZEN, Webhook.EVENT_ASSIST_CLAIM_CONFIRMED, Webhook.EVENT_ASSIST_CLAIM_UNVERIFIED));

        String secret = "whsec_test";
        Webhook webhook = new TouchQueClient(new TouchQueOptions().apiKey("tq_x").apiSecret(secret)).webhook();
        String now = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC).format(Instant.now());
        ObjectNode recovery = webhook.verify(signed(secret, Json.object().put("event", "RECOVERY_COMPLETED").put("externalUsername", "ada@acme.com")
                .put("integrationId", "i1").put("timestamp", now).put("jti", "j-rec").put("recoveryId", "rc1").put("status", "COMPLETED").put("method", "vouch")), null);
        assertEquals(Webhook.EVENT_RECOVERY_COMPLETED, Json.str(recovery, "event"));
        ObjectNode assist = webhook.verify(signed(secret, Json.object().put("event", "ASSIST_CLAIM_UNVERIFIED").put("externalUsername", "ada@acme.com")
                .put("integrationId", "i1").put("timestamp", now).put("jti", "j-as").put("caseCode", "K7P-2QX")), null);
        assertEquals(Webhook.EVENT_ASSIST_CLAIM_UNVERIFIED, Json.str(assist, "event"));
    }

    @Test
    void silentSignInRiskCheckVectors() throws Exception {
        ObjectNode fx = Support.fixture("silent-sign-in-vectors.json");
        for (JsonNode c : fx.get("riskCheck").get("cases")) {
            JsonNode response = c.get("response");
            JsonNode expected = c.get("expected");
            try (Support.Stub stub = new Support.Stub(seen -> Support.Answer.json(200, response))) {
                TouchQueClient tq = new TouchQueClient(new TouchQueOptions().apiKey("tq_x").apiSecret("s").baseUrl(stub.baseUrl));
                for (Risk.CheckResult res : List.of(Risk.parseCheck(response), tq.risk().check(new Risk.CheckOptions("jane@acme.com")))) {
                    assertEquals(expected.get("prompt").asBoolean(), res.prompt());
                    List<String> codes = new ArrayList<>();
                    expected.get("reasonCodes").forEach(x -> codes.add(x.asText()));
                    assertEquals(codes, res.reasons().stream().map(RiskReason::code).toList());
                    assertEquals(expected.get("assurance").asText(), res.assurance());
                }
            }
        }
    }

    @Test
    void approvalProofVectors() {
        ObjectNode fx = Support.fixture("approval-proof-vectors.json");
        for (JsonNode c : fx.get("digest_cases")) {
            List<LoginDetail> details = Details.fromJson(c.get("details") != null && c.get("details").isArray() ? c.get("details") : c.get("details_object"));
            assertEquals(c.get("digest").asText(), Details.digest(details));
        }
        for (JsonNode c : fx.get("cases")) {
            JsonNode o = c.get("options");
            ApprovalProof.Options options = new ApprovalProof.Options(o.get("requestId").asText(), o.get("type").asText())
                    .challengeCode(Json.str(o, "challengeCode"))
                    .expectedPublicKey(Json.str(o, "expectedPublicKey"))
                    .allowUnpinnedKey(o.has("allowUnpinnedKey") && o.get("allowUnpinnedKey").asBoolean());
            if (o.get("details") != null && !o.get("details").isNull()) options.details(Details.fromJson(o.get("details")));
            assertEquals(c.get("expected").asBoolean(), ApprovalProof.verify(c.get("proof"), options), c.path("name").asText());
        }
        assertFalse(ApprovalProof.verify(Json.object().put("version", "v2").put("algorithm", "ECDSA-P256-SHA256").put("publicKey", "!!").put("message", "x").put("signature", "%%"),
                new ApprovalProof.Options("r", "LOGIN").allowUnpinnedKey(true)));
    }

    @Test
    void detailsAreTrimmedLikeTheApi() {
        // The API trims with JavaScript's trim: NBSP, U+FEFF, U+2028 and U+3000 go; other control characters stay.
        assertEquals(Details.digest(List.of(LoginDetail.of("Amount", "250 EUR"))),
                Details.digest(List.of(LoginDetail.of("\uFEFFAmount\u3000", "250 EUR\u00A0\u2028"))));
        assertEquals(List.of(LoginDetail.of("Amount", "250 EUR\u0001")), Details.normalize(List.of(LoginDetail.of("\tAmount ", "250 EUR\u0001 "))));
    }

    @Test
    void agentThumbprintAthApprovalTokenAndMatchingVectors() {
        ObjectNode fx = Support.fixture("agent-vectors.json");
        for (JsonNode v : fx.get("thumbprints")) assertEquals(v.get("thumbprint").asText(), AgentKeys.thumbprint(v.get("jwk")));
        for (JsonNode v : fx.get("ath")) assertEquals(v.get("ath").asText(), AgentKeys.accessTokenHash(v.get("accessToken").asText()));

        JsonNode at = fx.get("approvalToken");
        JsonNode jwks = at.get("jwks");
        Instant verifyAt = Instant.ofEpochSecond(at.get("verifyAt").asLong());
        Object details = Map.of("instructedAmount", Map.of("currency", "TRY", "amount", "500"), "creditorAccount", Map.of("iban", "TR33 0006 1005 1978 6457 8413 26"));
        ObjectNode claims = ApprovalToken.verifyWith(at.get("token").asText(), jwks, at.get("audience").asText(),
                new ApprovalToken.Expectation("ayse@example.com", "PAY_INVOICE", details), verifyAt);
        assertEquals(at.get("claims"), claims);
        String own = at.get("audience").asText();
        assertThrows(TouchQueApprovalMismatchException.class, () -> ApprovalToken.verifyWith(at.get("tampered").asText(), jwks, own, null, verifyAt));
        assertThrows(TouchQueApprovalMismatchException.class, () -> ApprovalToken.verifyWith(at.get("wrongType").asText(), jwks, own, null, verifyAt));
        assertThrows(TouchQueApprovalMismatchException.class, () -> ApprovalToken.verifyWith(at.get("token").asText(), jwks, own, null, verifyAt.plusSeconds(3600)));
        assertThrows(TouchQueApprovalMismatchException.class,
                () -> ApprovalToken.verifyWith(at.get("token").asText(), jwks, own, new ApprovalToken.Expectation("mallory@example.com", null, null), verifyAt));
        // The audience is required, and a token without aud is refused.
        assertTrue(assertThrows(TouchQueApprovalMismatchException.class,
                () -> ApprovalToken.verifyWith(at.get("token").asText(), jwks, "touchque:workspace:other", null, verifyAt)).getMessage().contains("another workspace"));
        assertTrue(assertThrows(TouchQueApprovalMismatchException.class,
                () -> ApprovalToken.verifyWith(at.get("token").asText(), jwks, null, null, verifyAt)).getMessage().contains("audience is required"));
        assertTrue(assertThrows(TouchQueApprovalMismatchException.class,
                () -> ApprovalToken.verifyWith(at.get("token").asText(), jwks, "", null, verifyAt)).getMessage().contains("audience is required"));
        JsonNode noAud = at.get("noAudience");
        assertTrue(assertThrows(TouchQueApprovalMismatchException.class,
                () -> ApprovalToken.verifyWith(noAud.get("token").asText(), noAud.get("jwks"), own, null, verifyAt)).getMessage().contains("names no workspace"));

        JsonNode authz = at.get("claims").get("authorization_details");
        for (JsonNode m : fx.get("matching")) {
            assertEquals(m.get("matches").asBoolean(), ApprovalToken.matches(authz, m.get("expect").deepCopy()), m.path("name").asText());
        }
    }

    @Test
    void guardTokensAreBoundAndExpire() {
        ObjectNode claims = Json.object().put("u", "a").put("a", "LOGIN").put("d", "").putNull("r").put("exp", System.currentTimeMillis() + 60_000);
        String token = Steps.signGuardToken("secret", claims);
        assertEquals("a", Json.str(Steps.verifyGuardToken("secret", token), "u"));
        assertNull(Steps.verifyGuardToken("other", token));
        assertNull(Steps.verifyGuardToken("secret", token.substring(0, token.length() - 2) + "xx"));
        claims.put("exp", System.currentTimeMillis() - 1);
        assertNull(Steps.verifyGuardToken("secret", Steps.signGuardToken("secret", claims)));
    }

    @Test
    void configRefusesSwappedKeysAndPlainHttp() {
        assertThrows(TouchQueConfigException.class, () -> new TouchQueClient(new TouchQueOptions().apiKey("secret").apiSecret("tq_key")));
        assertThrows(TouchQueConfigException.class, () -> new TouchQueClient(new TouchQueOptions().apiKey("tq_k").apiSecret("s").baseUrl("http://api.example.com")));
        assertNotNull(new TouchQueClient(new TouchQueOptions().apiKey("tq_k").apiSecret("s").baseUrl("http://127.0.0.1:9")));
    }

    @Test
    void errorsCarryCodeCaseCodeAndRetryAfter() throws Exception {
        try (Support.Stub stub = new Support.Stub(seen -> new Support.Answer(429,
                Map.of("code", "rate_limited", "error", "too_many_login_requests", "caseCode", "REF-USE"), Map.of("Retry-After", "60")))) {
            TouchQueClient tq = new TouchQueClient(new TouchQueOptions().apiKey("tq_x").apiSecret("s").baseUrl(stub.baseUrl));
            TouchQueApiException e = assertThrows(TouchQueApiException.class, () -> tq.login().request("a@b.com"));
            assertEquals(List.of(429, "rate_limited", "REF-USE", 60), List.of(e.status(), e.code(), e.caseCode(), e.retryAfter()));
        }
        TouchQueClient down = new TouchQueClient(new TouchQueOptions().apiKey("tq_x").apiSecret("s").baseUrl("http://127.0.0.1:9"));
        assertThrows(TouchQueNetworkException.class, () -> down.login().status("r1"));
        try (Support.Stub stub = new Support.Stub(seen -> new Support.Answer(302, null, Map.of("Location", "https://evil.example/")))) {
            TouchQueClient tq = new TouchQueClient(new TouchQueOptions().apiKey("tq_x").apiSecret("s").baseUrl(stub.baseUrl));
            assertEquals(302, assertThrows(TouchQueApiException.class, () -> tq.login().status("r1")).status());
        }
        assertTrue(true);
    }
}
