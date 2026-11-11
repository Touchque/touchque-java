package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.agents.TouchqueAgent;
import com.touchque.crypto.AgentKeys;
import com.touchque.crypto.ApprovalToken;
import com.touchque.crypto.Keys;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import com.touchque.resources.Agents;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * AI agents: management calls send what fixtures/agent-vectors.json says, and TouchqueAgent
 * signs in with its own key against the fake API, which checks the private_key_jwt assertion and
 * the DPoP proofs like the real API.
 */
class AgentsTest {
    private final Support.FakeApi api = Support.FakeApi.get();
    private final ObjectNode vectors = Support.fixture("agent-vectors.json");

    @BeforeEach
    void reset() {
        api.reset();
    }

    private TouchqueAgent agent(String id, Object key, String kid) {
        return new TouchqueAgent(new TouchqueAgent.Options().agentId(id).privateKey(key).kid(kid).baseUrl(api.baseUrl));
    }

    private static String create(TouchqueClient tq, String name, JsonNode publicKey, String... types) {
        return tq.agents().create(new Agents.CreateOptions(name, types.length == 0 ? List.of("LOGIN") : List.of(types)).publicKey(publicKey)).get("id").asText();
    }

    @Test
    void generateKeys() {
        AgentKeys.Pair ec = AgentKeys.generate();
        assertEquals("ES256", ec.publicJwk().get("alg").asText());
        assertEquals(AgentKeys.thumbprint(ec.publicJwk()), ec.publicJwk().get("kid").asText());
        assertFalse(ec.publicJwk().has("d"));
        assertEquals("Ed25519", AgentKeys.generate("EdDSA").publicJwk().get("crv").asText());
        assertThrows(TouchqueConfigException.class, () -> AgentKeys.generate("RS256"));
    }

    @Test
    void managementCallVectors() {
        TouchqueClient tq = api.client();
        AgentKeys.Pair k1 = AgentKeys.generate();
        AgentKeys.Pair k2 = AgentKeys.generate("EdDSA");
        String id = "";
        for (JsonNode v : vectors.get("calls")) {
            JsonNode a = v.get("args");
            String name = v.get("name").asText();
            switch (name) {
                case "create" -> {
                    List<String> types = new java.util.ArrayList<>();
                    a.get("allowedTypes").forEach(x -> types.add(x.asText()));
                    id = tq.agents().create(new Agents.CreateOptions(a.get("name").asText(), types).publicKey(k1.publicJwk())
                            .ownerEmail(Json.str(a, "ownerEmail")).platform(Json.str(a, "platform")).reviewInDays(Json.integer(a, "reviewInDays"))).get("id").asText();
                }
                case "list" -> tq.agents().list(Json.str(a, "status"));
                case "get" -> tq.agents().get(id);
                case "update" -> tq.agents().update(id, a);
                case "addKey" -> tq.agents().addKey(id, k2.publicJwk());
                case "removeKey" -> tq.agents().removeKey(id, k2.publicJwk().get("kid").asText());
                case "suspend" -> tq.agents().suspend(id, Json.str(a, "reason"));
                case "resume" -> tq.agents().resume(id);
                case "setPolicy" -> tq.agents().setPolicy(id, a.get("policy"));
                case "getWorkspacePolicy" -> tq.agents().getWorkspacePolicy();
                case "listEvents" -> tq.agents().listEvents(Json.str(a, "after"), null, Json.integer(a, "limit"));
                case "setWorkspacePolicy" -> tq.agents().setWorkspacePolicy(a.get("policy"));
                case "listBlocks" -> tq.agents().listBlocks(id);
                case "killSwitch" -> tq.agents().setKillSwitch(a.get("engaged").asBoolean(), Json.str(a, "reason"));
                case "killSwitchOff" -> tq.agents().setKillSwitch(a.get("engaged").asBoolean(), null);
                case "revoke" -> tq.agents().revoke(id);
                default -> throw new IllegalStateException(name);
            }
            JsonNode call = api.lastCall();
            JsonNode want = Json.parse(Json.write(v)
                    .replace("\"{publicKey}\"", Json.write(k1.publicJwk()))
                    .replace("\"{publicKey2}\"", Json.write(k2.publicJwk()))
                    .replace("{id}", id)
                    .replace("{kid}", TouchqueHttp.seg(k2.publicJwk().get("kid").asText())));
            assertEquals(want.get("method").asText(), call.get("method").asText(), name);
            assertEquals(want.get("path").asText(), call.get("path").asText(), name);
            if (want.hasNonNull("query")) assertEquals(want.get("path").asText() + "?" + want.get("query").asText(), call.get("url").asText(), name);
            if (want.hasNonNull("body")) assertEquals(want.get("body"), call.get("body"), name);
        }
        assertThrows(TouchqueConfigException.class, () -> create(tq, "x", k1.privateJwk()));
    }

    @Test
    void agentSignsInWithItsOwnKey() throws Exception {
        TouchqueClient tq = api.client();
        for (String alg : List.of("ES256", "EdDSA")) {
            AgentKeys.Pair keys = AgentKeys.generate(alg);
            String id = create(tq, "agent " + alg, keys.publicJwk());
            for (Object key : List.of(keys.privateJwk(), Json.write(keys.privateJwk()))) {
                JsonNode me = agent(id, key, null).me();
                assertEquals(id, me.get("agent").get("id").asText());
                assertEquals("agent:read approvals:request approvals:read vault:read", me.get("scope").asText());
            }
        }
        // An EC key as PEM too.
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        byte[][] xy = Keys.ecPoint(kp.getPublic());
        ObjectNode pub = Json.object().put("kty", "EC").put("crv", "P-256").put("x", Base64Url.encode(xy[0])).put("y", Base64Url.encode(xy[1]));
        String pem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(kp.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n";
        String pemId = create(tq, "pem", pub);
        assertEquals(pemId, agent(pemId, pem, null).me().get("agent").get("id").asText());
    }

    @Test
    void tokenIsReusedAndRefusalsCarryTheReason() {
        TouchqueClient tq = api.client();
        AgentKeys.Pair keys = AgentKeys.generate();
        String id = create(tq, "refused", keys.publicJwk());
        TouchqueAgent agent = agent(id, keys.privateJwk(), null);
        agent.me();
        agent.me();
        int tokenCalls = 0;
        for (JsonNode c : api.calls()) tokenCalls += "/agents/token".equals(c.get("path").asText()) ? 1 : 0;
        assertEquals(1, tokenCalls);

        tq.agents().suspend(id, "looping");
        TouchqueApiException e = assertThrows(TouchqueApiException.class, agent::me);
        assertEquals(List.of(403, "agent_blocked", "suspended"), List.of(e.status(), e.code(), e.reason()));
        TouchqueApiException fresh = assertThrows(TouchqueApiException.class, () -> agent(id, keys.privateJwk(), null).me());
        assertEquals(List.of("unauthorized_client", "suspended"), List.of(fresh.code(), fresh.reason()));
        tq.agents().resume(id);

        TouchqueApiException stranger = assertThrows(TouchqueApiException.class,
                () -> agent(id, AgentKeys.generate().privateJwk(), keys.publicJwk().get("kid").asText()).me());
        assertEquals(List.of(401, "invalid_client"), List.of(stranger.status(), stranger.code()));

        tq.agents().setKillSwitch(true, "incident");
        assertEquals("workspace_paused", assertThrows(TouchqueApiException.class, agent::me).reason());
        tq.agents().setKillSwitch(false, null);
        assertEquals(id, agent.me().get("agent").get("id").asText());
    }

    @Test
    void configurationErrors() {
        ObjectNode key = AgentKeys.generate().privateJwk();
        assertThrows(TouchqueConfigException.class, () -> agent("nope", key, null));
        assertThrows(TouchqueConfigException.class, () -> agent("agt_abcdefghijkmnpqrstuv", "not a key", null));
        assertThrows(TouchqueConfigException.class,
                () -> new TouchqueAgent(new TouchqueAgent.Options().agentId("agt_abcdefghijkmnpqrstuv").privateKey(key).baseUrl("http://api.example.com")));
        assertThrows(TouchqueConfigException.class, () -> agent("agt_abcdefghijkmnpqrstuv", AgentKeys.generate().publicJwk(), null));
    }

    @Test
    void tokenVault() {
        TouchqueClient tq = api.client();
        AgentKeys.Pair keys = AgentKeys.generate();
        String id = create(tq, "calendar", keys.publicJwk());
        TouchqueAgent agent = agent(id, keys.privateJwk(), null);
        JsonNode conn = tq.agents().vault().putConnection("google", "google", "acme.apps.googleusercontent.com", "g-secret", null, null, List.of(id));
        assertTrue(conn.get("hasClientSecret").asBoolean());
        JsonNode account = tq.agents().vault().deposit("google", "jane@example.com", "ya29.jane", "1//jane", 3599, "calendar.readonly");
        assertTrue(account.get("canRefresh").asBoolean());
        assertEquals(1, tq.agents().vault().listAccounts("jane@example.com").size());
        TouchqueAgent.ConnectionToken token = agent.getConnectionToken("jane@example.com", "google", null);
        assertEquals(List.of("ya29.jane", "Bearer", 3599, "calendar.readonly", "google"),
                List.of(token.accessToken(), token.tokenType(), token.expiresIn(), token.scope(), token.connection()));
        assertEquals("not_connected", assertThrows(TouchqueApiException.class, () -> agent.getConnectionToken("john@example.com", "google", null)).code());
        tq.agents().vault().removeAccount("google", "jane@example.com");
        assertEquals(Json.parse("{\"removed\":true,\"tokensDeleted\":0}"), tq.agents().vault().removeConnection("google"));
    }

    @Test
    void askWaitVerifyRedeem() {
        TouchqueClient tq = api.client();
        String user = "agent-approvals@example.com";
        api.link(user);
        tq.actionTypes().define("PAY_INVOICE", null, false);
        AgentKeys.Pair keys = AgentKeys.generate();
        String id = create(tq, "Invoice bot", keys.publicJwk(), "PAY_INVOICE");
        TouchqueAgent agent = agent(id, keys.privateJwk(), null);
        JsonNode payment = vectors.get("approvalToken").get("claims").get("authorization_details").get(0);

        TouchqueAgent.ApprovalState ask = agent.requestApproval(user, "PAY_INVOICE", List.of(payment), new TouchqueAgent.ApprovalOptions().reason("October rent"));
        assertEquals(List.of("pending", "47"), List.of(ask.status(), ask.challengeCode()));
        api.approve(ask.approvalId());
        String token = agent.waitForApproval(ask.approvalId(), Duration.ofSeconds(10), Duration.ofMillis(500)).approvalToken();

        AtomicReference<String> shown = new AtomicReference<>();
        TouchqueAgent.ApprovalState required = agent.requireApproval(user, "PAY_INVOICE", List.of(payment), null, s -> {
            shown.set(s.challengeCode());
            api.approve(s.approvalId());
        }, Duration.ofSeconds(10));
        assertEquals("47", shown.get());
        assertFalse(required.approvalToken() == null || required.approvalToken().isEmpty());

        // The workspace's own audience comes from GET /agents/approval-audience; another one is refused.
        assertEquals("touchque:workspace:fake-workspace", tq.agents().approvalAudience());
        JsonNode claims = tq.agents().verifyApprovalToken(token, null, new ApprovalToken.Expectation(user, null, payment));
        assertEquals(id, claims.get("act").get("sub").asText());
        TouchqueApprovalMismatchException other = assertThrows(TouchqueApprovalMismatchException.class,
                () -> tq.agents().verifyApprovalToken(token, "touchque:workspace:other", null));
        assertTrue(other.getMessage().contains("another workspace"));
        ObjectNode wrongAmount = payment.deepCopy();
        wrongAmount.set("instructedAmount", Json.object().put("currency", "TRY").put("amount", "5000.00"));
        TouchqueApprovalMismatchException mismatch = assertThrows(TouchqueApprovalMismatchException.class,
                () -> tq.agents().redeemApproval(token, new ApprovalToken.Expectation(null, null, wrongAmount)));
        assertTrue(mismatch.getMessage().contains("differ"));
        JsonNode approval = tq.agents().redeemApproval(token, new ApprovalToken.Expectation(user, "PAY_INVOICE",
                Map.of("type", "payment_initiation", "instructedAmount", Map.of("currency", "try", "amount", "500"))));
        assertEquals(ask.approvalId(), approval.get("id").asText());
        assertEquals("already_redeemed", assertThrows(TouchqueApiException.class, () -> tq.agents().redeemApproval(token, null)).code());

        TouchqueAgent.ApprovalState ask2 = agent.requestApproval(user, "PAY_INVOICE", List.of(payment), new TouchqueAgent.ApprovalOptions().presence("background"));
        assertNull(ask2.challengeCode());
        api.reject(ask2.approvalId());
        TouchqueApprovalException rejected = assertThrows(TouchqueApprovalException.class,
                () -> agent.waitForApproval(ask2.approvalId(), Duration.ofSeconds(10), Duration.ofMillis(500)));
        assertEquals("rejected", rejected.status());
    }

    @Test
    void blocksAndMandates() {
        TouchqueClient tq = api.client();
        String blockedId = create(tq, "blocked", AgentKeys.generate().publicJwk());
        api.post("/__test/agent-block", Map.of("agentId", blockedId, "user", "jane@example.com"));
        assertEquals("not_me", tq.agents().listBlocks(blockedId).get(0).get("reason").asText());
        tq.agents().liftBlock(blockedId, "jane@example.com");
        assertEquals("/agents/" + blockedId + "/blocks/jane%40example.com", api.lastCall().get("path").asText());
        assertTrue(tq.agents().listBlocks(blockedId).isEmpty());

        String user = "agent-mandates@example.com";
        api.link(user);
        tq.actionTypes().define("PAY_INVOICE", null, false);
        AgentKeys.Pair keys = AgentKeys.generate();
        String id = create(tq, "Mandate bot", keys.publicJwk(), "PAY_INVOICE");
        TouchqueAgent agent = agent(id, keys.privateJwk(), null);
        JsonNode payment = vectors.get("approvalToken").get("claims").get("authorization_details").get(0);
        JsonNode mandate = agent.requestMandate(user, "PAY_INVOICE", 2, new TouchqueAgent.MandateAmount("TRY", "1000"), new TouchqueAgent.MandateOptions().validFor(3600));
        assertEquals("pending", mandate.get("status").asText());
        String mandateId = mandate.get("mandateId").asText();
        JsonNode requests = api.get("/__test/requests");
        api.approve(requests.get(requests.size() - 1).get("id").asText());
        assertEquals("active", agent.getMandate(mandateId).get("status").asText());
        TouchqueAgent.ApprovalState used = agent.requestApproval(user, "PAY_INVOICE", List.of(payment), new TouchqueAgent.ApprovalOptions().mandateId(mandateId));
        assertEquals(List.of("approved", 1), List.of(used.status(), used.mandate().get("usedCount").asInt()));
        assertEquals(mandateId, tq.agents().listMandates(id, user).get(0).get("mandateId").asText());
        assertEquals("revoked", tq.agents().revokeMandate(id, mandateId).get("status").asText());
        assertEquals("mandate_revoked", assertThrows(TouchqueApiException.class,
                () -> agent.requestApproval(user, "PAY_INVOICE", List.of(payment), new TouchqueAgent.ApprovalOptions().mandateId(mandateId))).code());
    }
}
