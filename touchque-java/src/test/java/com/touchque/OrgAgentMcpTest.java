package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.agents.McpAuth;
import com.touchque.agents.TouchqueOrgAgent;
import com.touchque.crypto.AgentKeys;
import com.touchque.crypto.SigningKey;
import com.touchque.internal.Json;
import com.touchque.resources.Offline;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** An organization's AI agent on Touchque SSO, McpAuth and outage verifiers, against the fake API. */
class OrgAgentMcpTest {
    private static final String APP = "tqapp_paymentsapi0000000000";
    private static final String RESOURCE = "https://mcp.acme.example/mcp";
    private final Support.FakeApi api = Support.FakeApi.get();

    @BeforeEach
    void reset() {
        api.reset();
    }

    private record Res(int status, JsonNode body) {
    }

    private Res resource(Map<String, String> headers) throws Exception {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(api.baseUrl + "/__test/resource")).GET();
        headers.forEach(req::header);
        HttpResponse<String> res = HttpClient.newHttpClient().send(req.build(), HttpResponse.BodyHandlers.ofString());
        return new Res(res.statusCode(), Json.parseObject(res.body()));
    }

    @Test
    void ownKeyTokenAndCalls() throws Exception {
        AgentKeys.Pair keys = AgentKeys.generate();
        String id = "oagt_abcdefghijkmnpqrstuv";
        api.post("/__test/org-agent", Map.of("agentId", id, "publicKey", keys.publicJwk(), "audiences", List.of(APP), "scopes", List.of("invoices:read", "payments:create")));
        TouchqueOrgAgent agent = new TouchqueOrgAgent(new TouchqueOrgAgent.Options().agentId(id).privateKey(keys.privateJwk()).issuer(api.baseUrl));
        TouchqueOrgAgent.Token token = agent.getToken(null, "invoices:read");
        assertEquals(List.of("DPoP", 300, "invoices:read"), List.of(token.tokenType(), token.expiresIn(), token.scope()));
        assertSame(token, agent.getToken(null, "invoices:read"));
        Map<String, String> headers = agent.authorization("GET", api.baseUrl + "/__test/resource", null, "invoices:read");
        Res res = resource(headers);
        assertEquals(200, res.status());
        assertEquals(Json.toNode(Map.of("ok", true, "sub", id, "aud", APP, "via", "key")), res.body());
        assertEquals(401, resource(headers).status()); // a proof is for one request
        assertEquals("invalid_scope", assertThrows(TouchqueApiException.class, () -> agent.getToken(null, "payments:refund")).code());
    }

    @Test
    void platformToken() throws Exception {
        String id = "oagt_bbbbbbbbbbbbbbbbbbbb";
        api.post("/__test/org-agent", Map.of("agentId", id, "workload", Map.of("subject", "repo:acme/payments:ref:refs/heads/main", "audience", "touchque"),
                "audiences", List.of(APP), "scopes", List.of("invoices:read")));
        java.util.function.Function<String, Supplier<String>> platform = sub -> () -> api.post("/__test/workload-token", Map.of("sub", sub, "aud", "touchque")).get("token").asText();
        TouchqueOrgAgent agent = new TouchqueOrgAgent(new TouchqueOrgAgent.Options().agentId(id).issuer(api.baseUrl).assertion(platform.apply("repo:acme/payments:ref:refs/heads/main")));
        assertEquals("workload", resource(agent.authorization("GET", api.baseUrl + "/__test/resource", null, null)).body().get("via").asText());
        TouchqueOrgAgent wrong = new TouchqueOrgAgent(new TouchqueOrgAgent.Options().agentId(id).issuer(api.baseUrl).assertion(platform.apply("repo:evil/x")));
        assertThrows(TouchqueApiException.class, wrong::getToken);
    }

    @Test
    void forAMember() throws Exception {
        AgentKeys.Pair keys = AgentKeys.generate("EdDSA");
        String id = "oagt_cccccccccccccccccccc";
        api.post("/__test/org-agent", Map.of("agentId", id, "publicKey", keys.publicJwk(), "audiences", List.of(APP), "scopes", List.of("payments:create"),
                "delegation", List.of("token_exchange", "ciba"), "sharedAccounts", List.of("k3JInstagramAcme01")));
        TouchqueOrgAgent agent = new TouchqueOrgAgent(new TouchqueOrgAgent.Options().agentId(id).privateKey(keys.privateJwk()).issuer(api.baseUrl));
        String url = api.baseUrl + "/__test/resource";

        TouchqueOrgAgent.Token exchanged = agent.exchangeToken("member:ada@acme.com", null, null);
        assertEquals("ada@acme.com", resource(Map.of("Authorization", "DPoP " + exchanged.accessToken(), "DPoP", agent.dpopProof("GET", url, exchanged.accessToken())))
                .body().get("sub").asText());
        TouchqueOrgAgent.ConnectionToken google = agent.getConnectionToken("member:ada@acme.com", "google", "email");
        assertEquals(List.of("ya29.ada@acme.com", "Bearer", 3599, "email", "google"),
                List.of(google.accessToken(), google.tokenType(), google.expiresIn(), google.scope(), google.connection()));
        assertEquals("invalid_grant", assertThrows(TouchqueApiException.class, () -> agent.getConnectionToken("member:ada@acme.com", "github", null)).code());

        Map<String, Object> payment = Map.of("type", "payment_initiation", "instructedAmount", Map.of("currency", "TRY", "amount", "500.00"));
        TouchqueOrgAgent.MemberRequest ask = agent.askMember("ada@acme.com", new TouchqueOrgAgent.AskMemberOptions().bindingMessage("Pay invoice 42").authorizationDetails(List.of(payment)));
        assertEquals(List.of("42", 1), List.of(ask.bindingCode(), ask.interval()));
        api.post("/__test/ciba-answer", Map.of("authReqId", ask.authReqId(), "approve", true));
        TouchqueOrgAgent.Token approved = agent.waitForMember(ask);
        assertEquals(Json.toNode(List.of(payment)), approved.authorizationDetails());
        assertEquals(id, resource(Map.of("Authorization", "DPoP " + approved.accessToken(), "DPoP", agent.dpopProof("GET", url, approved.accessToken())))
                .body().get("act").asText());

        TouchqueOrgAgent.SharedAccountAsk shared = agent.askToOpenSharedAccount("k3JInstagramAcme01", "ada@acme.com", "Post the launch photo");
        assertEquals("waiting_member", shared.status());
        assertTrue(shared.openUrl().contains("/agent-ask?ask=" + shared.askId()));
        api.post("/__test/shared-ask-answer", Map.of("askId", shared.askId(), "status", "declined"));
        TouchqueOrgAgent.SharedAccountAskStatus ended = agent.waitForSharedAccount(shared, Duration.ofMillis(50));
        assertEquals("declined", ended.status());
        assertNull(ended.reason());
        assertNull(ended.caseCode());

        TouchqueOrgAgent.MemberRequest no = agent.askMember("ada@acme.com", null);
        api.post("/__test/ciba-answer", Map.of("authReqId", no.authReqId(), "approve", false));
        assertEquals("access_denied", assertThrows(TouchqueApiException.class, () -> agent.waitForMember(no)).code());
    }

    @Test
    void orgAgentConfigurationMistakes() {
        assertThrows(TouchqueConfigException.class,
                () -> new TouchqueOrgAgent(new TouchqueOrgAgent.Options().agentId("oagt_abcdefghijkmnpqrstuv").issuer("http://sso.example.com").assertion(() -> "x")));
        assertThrows(TouchqueConfigException.class, () -> new TouchqueOrgAgent(new TouchqueOrgAgent.Options().agentId("agt_nope").assertion(() -> "x")));
    }

    private String mcpToken(Map<String, Object> claims) {
        ObjectNode body = claims == null ? Json.object() : (ObjectNode) Json.toNode(claims);
        if (!body.has("aud")) body.put("aud", RESOURCE);
        if (!body.has("scope")) body.put("scope", "tickets:read");
        return api.post("/__test/mcp-token", body).get("token").asText();
    }

    private McpAuth mcp() {
        return new McpAuth(new McpAuth.Options(api.baseUrl + "/mcp-as", RESOURCE).tools(Map.of("search_tickets", "tickets:read", "delete_ticket", "tickets:delete")));
    }

    @Test
    void mcpMetadataTokensAndScopes() {
        McpAuth auth = mcp();
        assertEquals(List.of("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"), auth.metadataPaths());
        assertEquals(api.baseUrl + "/mcp-as", auth.protectedResourceMetadata().get("authorization_servers").get(0).asText());
        McpAuth.Claims claims = auth.verify("POST", RESOURCE, Map.of("Authorization", "Bearer " + mcpToken(null)));
        assertEquals("user-1", claims.sub());
        assertFalse(claims.dpopBound());
        assertEquals("https://tool.example/client.json", claims.clientId());
        assertEquals(List.of("tickets:read"), claims.scopes());
        auth.requireTool(claims, "search_tickets");
        TouchqueMcpAuthException e = assertThrows(TouchqueMcpAuthException.class, () -> auth.requireTool(claims, "delete_ticket"));
        assertEquals(403, e.status());
        assertTrue(e.wwwAuthenticate().contains("scope=\"tickets:delete\""));
        e = assertThrows(TouchqueMcpAuthException.class, () -> auth.verify("POST", RESOURCE, Map.of()));
        assertEquals(401, e.status());
        assertEquals("Bearer resource_metadata=\"https://mcp.acme.example/.well-known/oauth-protected-resource/mcp\"", e.wwwAuthenticate());
        for (Map<String, Object> bad : List.<Map<String, Object>>of(Map.of("aud", "https://other.example/mcp"), Map.of("iss", "https://evil.example/mcp"),
                Map.of("expiresIn", -120), Map.of("typ", "JWT"))) {
            String token = mcpToken(bad);
            assertEquals("invalid_token", assertThrows(TouchqueMcpAuthException.class,
                    () -> auth.verify("POST", RESOURCE, Map.of("Authorization", "Bearer " + token))).error(), bad.toString());
        }
    }

    @Test
    void mcpDpopBound() {
        McpAuth auth = mcp();
        SigningKey key = SigningKey.newEs256();
        ObjectNode jwk = key.publicJwk();
        String token = mcpToken(Map.of("jkt", AgentKeys.thumbprint(jwk)));
        java.util.function.Function<String, String> proof = htu -> {
            ObjectNode header = Json.object().put("typ", "dpop+jwt");
            header.set("jwk", jwk);
            return key.jws(header, Json.object().put("htm", "POST").put("htu", htu).put("iat", Instant.now().getEpochSecond())
                    .put("jti", UUID.randomUUID().toString()).put("ath", AgentKeys.accessTokenHash(token)));
        };
        assertThrows(TouchqueMcpAuthException.class, () -> auth.verify("POST", RESOURCE, Map.of("Authorization", "Bearer " + token)));
        String good = proof.apply(RESOURCE);
        assertTrue(auth.verify("POST", RESOURCE, Map.of("Authorization", "DPoP " + token, "DPoP", good)).dpopBound());
        assertEquals("invalid_dpop_proof", assertThrows(TouchqueMcpAuthException.class,
                () -> auth.verify("POST", RESOURCE, Map.of("Authorization", "DPoP " + token, "DPoP", good))).error());
        assertThrows(TouchqueMcpAuthException.class,
                () -> auth.verify("POST", RESOURCE, Map.of("Authorization", "DPoP " + token, "DPoP", proof.apply("https://other.example/mcp"))));
    }

    @Test
    void outageVerifiersFetchThenMatchOffline() {
        api.link("vpn@example.com");
        TouchqueClient tq = api.client();
        Instant now = Instant.now();
        long step = now.getEpochSecond() / 30;
        JsonNode v = tq.offline().totpVerifiers(List.of("vpn@example.com", "nobody@example.com"), step - 1, 4);
        assertEquals(1, v.get("users").size());
        JsonNode user = v.get("users").get(0);
        assertEquals("vpn@example.com", user.get("externalUsername").asText());
        assertEquals(step, Offline.matchTotpVerifier(v, user, "k7p-2qxa", now));
        assertNull(Offline.matchTotpVerifier(v, user, "K7P2QXB", now));
        assertNull(Offline.matchTotpVerifier(v, user, "K7P2QXA", now.plusSeconds(3600)));
        assertNull(Offline.matchTotpVerifier(v, user, "K7P2QX1", now));
        api.opts(Map.of("outageVerifiersDisabled", true));
        assertThrows(TouchqueApiException.class, () -> tq.offline().totpVerifiers(List.of("vpn@example.com"), null, null));
    }
}
