package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.agents.AgentCard;
import com.touchque.agents.CrossAppAccess;
import com.touchque.agents.IdJagVerifier;
import com.touchque.crypto.AgentKeys;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Json;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Cross App Access (ID-JAG) and A2A agent card signatures against the fake API: an app trades a
 * member's ID token for an ID-JAG at the identity provider and redeems it; an authorization
 * server checks one (issuer, audience, client, expiry, typ, once); a card signed in RFC 8785
 * form by the fake (JavaScript) verifies here with keys from its own host and fails when changed
 * or pointed elsewhere.
 */
class CrossAppAccessTest {
    private final Support.FakeApi api = Support.FakeApi.get();

    @BeforeEach
    void reset() {
        api.reset();
    }

    private IdJagVerifier verifier() {
        return new IdJagVerifier(new IdJagVerifier.Options(api.baseUrl + "/idp", "https://rs.example"));
    }

    private static String reason(Runnable f) {
        try {
            f.run();
            return "accepted";
        } catch (TouchqueIdJagException e) {
            return e.getMessage();
        }
    }

    private String mint(ObjectNode claims, String typ) {
        ObjectNode body = Json.object();
        body.set("claims", claims != null ? claims : Json.object());
        if (typ != null) body.put("typ", typ);
        return api.post("/__test/id-jag", body).get("assertion").asText();
    }

    @Test
    void requestRedeemAndVerify() {
        String idp = api.baseUrl + "/idp";
        CrossAppAccess.IdJagGrant jag = CrossAppAccess.requestIdJag(new CrossAppAccess.RequestOptions("tqapp_test", "tqs_test", "idtoken:ada", "https://rs.example")
                .issuer(idp).resource("https://rs.example/files"));
        assertEquals("files:read", jag.scope());
        TouchqueIdJagException refused = assertThrows(TouchqueIdJagException.class,
                () -> CrossAppAccess.requestIdJag(new CrossAppAccess.RequestOptions("tqapp_test", "wrong", "idtoken:ada", "https://rs.example").issuer(idp)));
        assertEquals(List.of("invalid_client", 401), List.of(refused.error(), refused.status()));

        IdJagVerifier v = verifier();
        IdJagVerifier.Claims claims = v.verify(jag.assertion(), "acme-at-rs");
        assertEquals(List.of("ada", "acme-at-rs", "files:read", "https://rs.example/files"),
                List.of(claims.sub(), claims.clientId(), String.join(" ", claims.scopes()), claims.resource()));
        assertEquals("already used", reason(() -> v.verify(jag.assertion(), "acme-at-rs")));
        JsonNode tokens = CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(api.baseUrl + "/rs/token", "acme-at-rs", jag.assertion()));
        assertEquals("Bearer", Json.str(tokens, "token_type"));
    }

    @Test
    void refusals() {
        IdJagVerifier v = verifier();
        assertEquals("issued to another client", reason(() -> v.verify(mint(null, null), "someone-else")));
        assertEquals("not for this authorization server", reason(() -> v.verify(mint(Json.object().put("aud", "https://evil.example"), null), "acme-at-rs")));
        ObjectNode twoAuds = Json.object();
        twoAuds.set("aud", Json.array().add("https://rs.example").add("https://b.example"));
        assertEquals("not for this authorization server", reason(() -> v.verify(mint(twoAuds, null), "acme-at-rs")));
        assertEquals("another issuer", reason(() -> v.verify(mint(Json.object().put("iss", "https://evil.example"), null), "acme-at-rs")));
        assertEquals("not an ID-JAG (typ oauth-id-jag+jwt)", reason(() -> v.verify(mint(null, "at+jwt"), "acme-at-rs")));
        assertEquals("expired", reason(() -> v.verify(mint(Json.object().put("exp", Instant.now().getEpochSecond() - 600), null), "acme-at-rs")));
        String[] parts = mint(null, null).split("\\.");
        ObjectNode c = Json.parseObject(new String(Base64Url.decode(parts[1]), StandardCharsets.UTF_8));
        c.put("sub", "mallory");
        assertEquals("signature does not verify", reason(() -> v.verify(parts[0] + "." + Base64Url.encode(Json.write(c)) + "." + parts[2], "acme-at-rs")));
    }

    private static String code(Runnable f) {
        try {
            f.run();
            return "verified";
        } catch (TouchqueAgentCardException e) {
            return e.error();
        }
    }

    @Test
    void agentCards() throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        String url = api.baseUrl + "/.well-known/agent-card.json";
        String card = http.send(HttpRequest.newBuilder(URI.create(url)).build(), HttpResponse.BodyHandlers.ofString()).body();
        assertEquals(new AgentCard.Verification("a2a-1", "ES256", "jku"), AgentCard.verify(card, new AgentCard.VerifyOptions().cardUrl(url)));
        String tampered = http.send(HttpRequest.newBuilder(URI.create(url + "?tamper=1")).build(), HttpResponse.BodyHandlers.ofString()).body();
        assertEquals("invalid_signature", code(() -> AgentCard.verify(tampered, new AgentCard.VerifyOptions().cardUrl(url))));
        assertEquals("untrusted_key", code(() -> AgentCard.verify(card, new AgentCard.VerifyOptions().cardUrl("https://agent.example/.well-known/agent-card.json"))));
        assertEquals("unsigned", code(() -> AgentCard.verify("{\"name\":\"x\"}", null)));

        AgentKeys.Pair keys = AgentKeys.generate("EdDSA");
        String signed = AgentCard.sign("{\"name\":\"Mine\",\"url\":\"https://mine.example/a2a\",\"skills\":[]}", keys.privateJwk(), "k1", null);
        ObjectNode jwk = keys.publicJwk().deepCopy().put("kid", "k1");
        assertEquals(new AgentCard.Verification("k1", "EdDSA", "keys"), AgentCard.verify(signed, new AgentCard.VerifyOptions().keys(List.of(jwk))));
        assertEquals("invalid_signature", code(() -> AgentCard.verify(signed.replace("mine.example", "evil.example"), new AgentCard.VerifyOptions().keys(List.of(jwk)))));

        JsonNode value = Json.parse("{\"€\":\"Euro\",\"\\r\":\"CR\",\"😀\":\"smile\",\"1\":\"one\",\"a\":[1e21,1e-7,0.5,-0,\"tab\\there\",1e-5,100.0]}");
        assertEquals("{\"\\r\":\"CR\",\"1\":\"one\",\"a\":[1e+21,1e-7,0.5,0,\"tab\\there\",0.00001,100],\"€\":\"Euro\",\"😀\":\"smile\"}", AgentCard.canonicalJson(value));
    }
}
