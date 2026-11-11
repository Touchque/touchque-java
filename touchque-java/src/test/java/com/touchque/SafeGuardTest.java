package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.crypto.SafeApproval;
import com.touchque.resources.SafeGuard;
import com.touchque.resources.SafeTx;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Safe Guard: the verifier against the shared vectors (fixtures/safe-guard-vectors.json, derived from the
 * reference project and shared with every server SDK), and request / status / wait against the fake API.
 */
class SafeGuardTest {
    private static final ObjectNode VECTORS = Support.fixture("safe-guard-vectors.json");
    private static final String KEY = VECTORS.path("approverKey").asText();
    private static final Instant NOW = Instant.ofEpochSecond(VECTORS.path("now").asLong());

    private static JsonNode vector(String name) {
        for (JsonNode v : VECTORS.path("vectors")) if (v.path("name").asText().equals(name)) return v;
        throw new IllegalArgumentException(name);
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(a -> out.add(a.asText()));
        return out;
    }

    @Test
    void everyVector() {
        for (JsonNode v : VECTORS.path("vectors")) {
            String name = v.path("name").asText();
            SafeTx tx = SafeTx.fromJson(v.path("safeTx"));
            assertEquals(v.path("safeTxHash").asText(), SafeApproval.safeTxHash(tx), name);
            assertEquals(v.path("governanceHash").asText(), SafeApproval.governanceHash(tx), name);
            assertEquals(v.path("message").asText(), SafeApproval.message(v.path("purpose").asText(), tx.chainId(), tx.guard(), tx.safe(),
                    v.path("subject").asText(), v.path("expiresAt").asLong(), v.path("displayDigest").asText()), name);
            if (v.has("rows")) {
                List<SafeApproval.Row> rows = new ArrayList<>();
                v.path("rows").forEach(r -> rows.add(new SafeApproval.Row(r.path("label").asText(), r.path("value").asText())));
                assertEquals(v.path("rowsDigest").asText(), SafeApproval.displayDigest(rows), name);
            }
            assertEquals(new SafeApproval.Verification(true, null, v.path("purpose").asText(), tx.approverIndex(), v.path("expiresAt").asLong(),
                    v.path("displayDigest").asText(), v.path("safeTxHash").asText(), v.path("governanceHash").asText()),
                    SafeApproval.verify(tx, v.path("approval").asText(), KEY,
                            new SafeApproval.VerifyOptions().now(NOW).approverIndex(tx.approverIndex()).purpose(v.path("purpose").asText())), name);
        }
    }

    @Test
    void everyCheck() {
        for (JsonNode c : VECTORS.path("checks")) {
            JsonNode o = c.path("options");
            SafeApproval.VerifyOptions options = new SafeApproval.VerifyOptions()
                    .now(o.has("now") ? Instant.ofEpochSecond(o.path("now").asLong()) : NOW)
                    .purpose(o.has("purpose") ? o.path("purpose").asText() : null)
                    .approverIndex(o.has("approverIndex") ? o.path("approverIndex").asInt() : null)
                    .displayDigest(o.has("displayDigest") ? o.path("displayDigest").asText() : null);
            String key = c.has("key") ? c.path("key").asText() : KEY;
            SafeApproval.Verification got = SafeApproval.verify(SafeTx.fromJson(vector(c.path("vector").asText()).path("safeTx")), c.path("approval").asText(), key, options);
            String reason = c.path("reason").isNull() ? null : c.path("reason").asText();
            assertEquals(reason, got.reason(), c.path("name").asText());
            assertEquals(reason == null, got.valid(), c.path("name").asText());
            if (c.has("purpose")) assertEquals(c.path("purpose").asText(), got.purpose(), c.path("name").asText());
        }
    }

    @Test
    void trailerAndScheduleCall() {
        JsonNode w = VECTORS.path("withApprovals");
        assertEquals(w.path("expected").asText(), SafeApproval.withApprovals(w.path("ownerSignatures").asText(), strings(w.path("approvals"))));
        JsonNode s = VECTORS.path("scheduleCall");
        assertEquals(s.path("expected").asText(), SafeApproval.scheduleCall(s.path("safe").asText(), s.path("governanceHash").asText(), strings(s.path("approvals"))));
        SafeTx bad = SafeTx.fromJson(VECTORS.path("vectors").get(0).path("safeTx")).operation(2);
        assertThrows(TouchqueConfigException.class, () -> SafeApproval.safeTxHash(bad));
    }

    @Test
    void requestWaitAndCheckTheApprovalHere() {
        Support.FakeApi api = Support.FakeApi.get();
        api.reset();
        api.link("treasurer@acme.com");
        JsonNode v = vector("bybit_pattern");
        api.opts(Map.of("safeTxView", Map.of("class", v.path("class").asText(), "flags", List.of("delegatecall"), "safeTxHash", v.path("safeTxHash").asText(),
                "governanceHash", v.path("governanceHash").asText(), "purpose", v.path("purpose").asText())));
        TouchqueClient tq = api.client();
        SafeTx tx = SafeTx.fromJson(v.path("safeTx"));
        JsonNode sent = tq.safeGuard().request(new SafeGuard.RequestOptions("treasurer@acme.com", "safe_payment", tx).referenceId("tx-1"));
        assertEquals(v.path("governanceHash").asText(), sent.path("safeTx").path("governanceHash").asText());
        JsonNode call = api.lastCall();
        assertEquals("/safe-guard/approvals", call.path("path").asText());
        assertEquals("1", call.path("body").path("safeTx").path("chainId").asText());
        assertEquals(172800, call.path("body").path("safeTx").path("config").path("govDelay").asInt());
        assertEquals("tx-1", call.path("body").path("referenceId").asText());
        String requestId = sent.path("requestId").asText();
        assertFalse(tq.safeGuard().status(requestId).path("safeTx").has("approval"));

        api.post("/__test/approve", Map.of("id", requestId, "safeTx", Map.of("approval", v.path("approval").asText(), "expiresAt", v.path("expiresAt").asLong())));
        JsonNode done = tq.safeGuard().waitForApproval(requestId, Duration.ofSeconds(5), Duration.ofMillis(10));
        assertEquals("CONFIRMED", done.path("status").asText());
        SafeApproval.Verification check = SafeApproval.verify(tx, done.path("safeTx").path("approval").asText(), KEY,
                new SafeApproval.VerifyOptions().now(NOW).approverIndex(done.path("safeTx").path("approverIndex").asInt()).purpose("schedule"));
        assertTrue(check.valid());
        assertEquals("schedule", check.purpose());
        // Without a purpose only an ordinary approval passes: a schedule approval is no permission to execute.
        assertEquals("signature_invalid", SafeApproval.verify(tx, done.path("safeTx").path("approval").asText(), KEY,
                new SafeApproval.VerifyOptions().now(NOW)).reason());

        String again = tq.safeGuard().request(new SafeGuard.RequestOptions("treasurer@acme.com", "safe_payment", tx)).path("requestId").asText();
        api.reject(again);
        assertThrows(TouchqueRejectedException.class, () -> tq.safeGuard().waitForApproval(again, Duration.ofSeconds(5), Duration.ofMillis(10)));
    }
}
