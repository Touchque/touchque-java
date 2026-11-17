package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import com.touchque.resources.Identity;
import com.touchque.resources.Webhook;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

/**
 * Touchque Login's passkey domain, custom domains (overview, get, verify) and user store against a
 * stub of the Management API: what is sent,
 * what comes back and how refusals map; and the user store's own requests, checked by the webhook
 * verify (the shared vectors run in VectorTest).
 */
class IdentitySettingsTest {
    private static final String STORE = "https://api.acme.test/touchque/user-store";

    // Signed with the API's own signer and sent exactly as
    // the API does: JSON.stringify({ event, tenant, ...fields, timestamp, jti, signature }),
    // the signature over the payload's canonical form with the workspace's API secret.
    private static final String SECRET = "test_secret_user_store";
    private static final String VERIFY_PASSWORD = "{\"event\":\"user_store.verify_password\",\"tenant\":\"acme\",\"email\":\"zoe@acme.test\","
            + "\"password\":\"pässwörd 🔑 \\\"1\\\" \\\\ € 😀 </x>\u2028\",\"timestamp\":\"2026-11-17T06:00:00.000Z\","
            + "\"jti\":\"9b2f6a2e-0c1d-4c55-9a51-15000000000a\",\"signature\":\"e0851813913df39f6e171218050bb4feecac8e435cf8ad05977c718c8c72ae01\"}";
    private static final String VERIFY_PASSWORD_SIGNATURE = "e0851813913df39f6e171218050bb4feecac8e435cf8ad05977c718c8c72ae01";
    private static final String GET_USER = "{\"event\":\"user_store.get_user\",\"tenant\":\"acme\",\"email\":\"zoe@acme.test\","
            + "\"timestamp\":\"2026-11-17T06:00:00.000Z\",\"jti\":\"9b2f6a2e-0c1d-4c55-9a51-8000000000a\","
            + "\"signature\":\"bdaa0efa8c850e29c9d99f3d2bbd8456facd4e4c7b1b89c9ba9f4e3e16cb5960\"}";
    private static final String GET_USER_SIGNATURE = "bdaa0efa8c850e29c9d99f3d2bbd8456facd4e4c7b1b89c9ba9f4e3e16cb5960";
    private static final String PING = "{\"event\":\"user_store.ping\",\"tenant\":\"acme\",\"timestamp\":\"2026-11-17T06:00:00.000Z\","
            + "\"jti\":\"9b2f6a2e-0c1d-4c55-9a51-4000000000a\",\"signature\":\"15e600314e96a48ba3a1c2be399f215ac9c97e11381ff936fadbf21a893273b0\"}";
    private static final String PING_SIGNATURE = "15e600314e96a48ba3a1c2be399f215ac9c97e11381ff936fadbf21a893273b0";

    private static TouchqueClient client(Support.Stub stub) {
        return new TouchqueClient(new TouchqueOptions().apiKey("tq_x").apiSecret("s").baseUrl(stub.baseUrl));
    }

    private static ObjectNode obj(String json) {
        return (ObjectNode) Json.parse(json);
    }

    private static List<String> lines(List<Support.Seen> seen) {
        return seen.stream().map(s -> s.method() + " " + s.path()).toList();
    }

    @Test
    void passkeyDomainIsSentAsGivenAndNullClearsIt() throws Exception {
        List<Support.Seen> seen = new CopyOnWriteArrayList<>();
        ObjectNode tenant = obj("{\"slug\":\"acme\",\"issuer\":\"https://login.acme.com\",\"passkeyDomain\":\"acme.com\",\"signInMethods\":{\"password\":true,\"passkey\":true,\"emailCode\":false}}");
        try (Support.Stub stub = new Support.Stub(s -> {
            seen.add(s);
            return Support.Answer.json(200, tenant);
        })) {
            TouchqueClient tq = client(stub);
            assertEquals(tenant, tq.identity().setPasskeyDomain("acme.com"));
            tq.identity().setPasskeyDomain(null);
        }
        assertEquals(List.of("PUT /identity/tenant", "PUT /identity/tenant"), lines(seen));
        // Only passkeyDomain (a tenant PUT changes the fields it carries); null is sent, since a field left out changes nothing.
        assertEquals("{\"passkeyDomain\":\"acme.com\"}", seen.get(0).body());
        assertEquals("{\"passkeyDomain\":null}", seen.get(1).body());
        assertEquals("application/json", seen.get(1).header("Content-Type"));
    }

    @Test
    void passkeyDomainRefusalsKeepTheApiCodeAndCount() throws Exception {
        ObjectNode passkeysExist = obj("{\"error\":\"passkeys_exist\",\"field\":\"passkeyDomain\",\"count\":3,"
                + "\"message\":\"3 customer passkeys belong to the current setting and would stop working\"}");
        ObjectNode notYours = obj("{\"error\":\"not_your_domain\",\"field\":\"passkeyDomain\",\"message\":\"example.com must be one of your verified custom domains\"}");
        ObjectNode invalid = obj("{\"error\":\"invalid_request\",\"field\":\"passkeyDomain\",\"message\":\"passkeyDomain must be a domain like example.com, or null\"}");
        ObjectNode unavailable = obj("{\"error\":\"organization_unavailable\",\"field\":\"passkeyDomain\",\"message\":\"Your organization’s verified domains could not be read; try again\"}");
        // Before Touchque Login is set up, a tenant PUT sets it up and needs a slug: the refusal is for slug.
        ObjectNode noTenant = obj("{\"error\":\"invalid_request\",\"field\":\"slug\",\"message\":\"slug must be 3–63 lowercase letters, digits or hyphens\"}");
        try (Support.Stub stub = new Support.Stub(s -> s.body().contains("acme.com") ? Support.Answer.json(409, passkeysExist)
                : s.body().contains("example.com") ? Support.Answer.json(409, notYours)
                : s.body().contains("acme.org") ? Support.Answer.json(409, unavailable)
                : s.body().contains("acme.net") ? Support.Answer.json(400, noTenant) : Support.Answer.json(400, invalid))) {
            TouchqueClient tq = client(stub);
            TouchqueApiException e = assertThrows(TouchqueApiException.class, () -> tq.identity().setPasskeyDomain("acme.com"));
            assertEquals(List.of(409, "passkeys_exist", 3, "passkeyDomain"), List.of(e.status(), e.error(), e.body().path("count").asInt(), e.body().path("field").asText()));
            assertEquals("3 customer passkeys belong to the current setting and would stop working", e.getMessage());
            assertFalse(e instanceof TouchqueFeatureException);
            assertNull(e.code());   // the Management API names a refusal in error(), not code()
            TouchqueApiException other = assertThrows(TouchqueApiException.class, () -> tq.identity().setPasskeyDomain("example.com"));
            assertEquals(List.of(409, "not_your_domain"), List.of(other.status(), other.error()));
            TouchqueApiException bad = assertThrows(TouchqueApiException.class, () -> tq.identity().setPasskeyDomain("com"));
            assertEquals(List.of(400, "invalid_request", "passkeyDomain"), List.of(bad.status(), bad.error(), bad.body().path("field").asText()));
            TouchqueApiException retry = assertThrows(TouchqueApiException.class, () -> tq.identity().setPasskeyDomain("acme.org"));
            assertEquals(List.of(409, "organization_unavailable"), List.of(retry.status(), retry.error()));
            TouchqueApiException notSetUp = assertThrows(TouchqueApiException.class, () -> tq.identity().setPasskeyDomain("acme.net"));
            assertEquals(List.of(400, "invalid_request", "slug"), List.of(notSetUp.status(), notSetUp.error(), notSetUp.body().path("field").asText()));
        }
    }

    @Test
    void customDomainsOverviewGetAndVerify() throws Exception {
        List<Support.Seen> seen = new CopyOnWriteArrayList<>();
        ObjectNode answer = obj("{\"domains\":[{\"id\":\"dom_1\",\"domain\":\"login.acme.com\",\"status\":\"verified\",\"primary\":true,"
                + "\"dns\":{\"at\":\"2026-11-17T06:00:00.000Z\",\"expected\":\"acme.login.touchque.com\",\"points\":\"here\",\"cname\":[\"acme.login.touchque.com\"],"
                + "\"addresses\":[],\"cloudflareProxy\":false,\"caa\":null,\"caaBlocks\":false,\"problems\":[]},\"autoCheckUntil\":\"2026-11-20T06:00:00.000Z\"}],"
                + "\"verifiedDomains\":[\"acme.com\"],\"slugPasskeys\":2}");
        ObjectNode checked = obj("{\"id\":\"dom 1/x\",\"domain\":\"login.acme.org\",\"status\":\"pending\",\"primary\":false,\"lastError\":\"TXT record not found\",\"dns\":null}");
        try (Support.Stub stub = new Support.Stub(s -> {
            seen.add(s);
            return Support.Answer.json(200, s.method().equals("POST") ? checked : answer);
        })) {
            TouchqueClient tq = client(stub);
            Identity.CustomDomainsOverview all = tq.identity().customDomains().overview();
            assertEquals(List.of(answer.get("domains").get(0)), all.domains());
            assertEquals(List.of("acme.com"), all.verifiedDomains());
            assertEquals(2, all.slugPasskeys());
            // getCustomDomains() is an alias of overview().
            assertEquals(all, tq.identity().getCustomDomains());
            // list() is still the array alone, each domain whole (dns, autoCheckUntil).
            assertEquals(answer.get("domains"), tq.identity().customDomains().list());
            // get(id) finds the domain in the list: the API has no call for one domain.
            assertEquals(answer.get("domains").get(0), tq.identity().customDomains().get("dom_1"));
            TouchqueApiException missing = assertThrows(TouchqueApiException.class, () -> tq.identity().customDomains().get("dom_2"));
            assertEquals(List.of(404, "not_found", "No custom domain with this id"), List.of(missing.status(), missing.error(), missing.getMessage()));
            assertEquals("No custom domain with this id", missing.body().path("message").asText());
            assertFalse(missing instanceof TouchqueFeatureException);
            assertNull(missing.code());
            assertThrows(TouchqueApiException.class, () -> tq.identity().customDomains().get(null));
            // verify(id): POST with {}, the id path-encoded; the answer is the domain.
            assertEquals(checked, tq.identity().customDomains().verify("dom 1/x"));
        }
        assertEquals(List.of("GET /identity/custom-domains", "GET /identity/custom-domains", "GET /identity/custom-domains", "GET /identity/custom-domains",
                "GET /identity/custom-domains", "GET /identity/custom-domains", "POST /identity/custom-domains/dom%201%2Fx/verify"), lines(seen));
        assertEquals("{}", seen.get(6).body());
        assertEquals("application/json", seen.get(6).header("Content-Type"));
    }

    @Test
    void customDomainOverviewReadsAnswersLeniently() {
        // The organization's domains could not be read: null, not an empty list.
        Identity.CustomDomainsOverview unread = Identity.CustomDomainsOverview.of(obj("{\"domains\":[],\"verifiedDomains\":null,\"slugPasskeys\":0}"));
        assertEquals(List.of(), unread.domains());
        assertNull(unread.verifiedDomains());
        assertEquals(0, unread.slugPasskeys());
        Identity.CustomDomainsOverview empty = Identity.CustomDomainsOverview.of(Json.object());
        assertEquals(List.of(List.of(), 0), List.of(empty.domains(), empty.slugPasskeys()));
        assertNull(empty.verifiedDomains());
        assertEquals(List.of(), Identity.CustomDomainsOverview.of(obj("{\"verifiedDomains\":[]}")).verifiedDomains());
        assertEquals(0, Identity.CustomDomainsOverview.of(null).slugPasskeys());
    }

    @Test
    void userStoreSendsOnlyWhatIsGivenAndReturnsTheAnswerWhole() throws Exception {
        List<Support.Seen> seen = new CopyOnWriteArrayList<>();
        ObjectNode view = obj("{\"url\":\"" + STORE + "\",\"enabled\":true,\"active\":true,\"movedIn\":12,"
                + "\"lastCall\":{\"at\":\"2026-11-17T06:00:00.000Z\",\"event\":\"user_store.verify_password\",\"ok\":true,\"status\":200,\"ms\":84,\"error\":null},"
                + "\"paused\":false,\"updatedAt\":\"2026-11-16T20:00:00.000Z\",\"signing\":\"Signed like Touchque webhooks\"}");
        ObjectNode ping = obj("{\"ok\":false,\"error\":\"answered 500\",\"ms\":31}");
        try (Support.Stub stub = new Support.Stub(s -> {
            seen.add(s);
            if (s.method().equals("DELETE")) return Support.Answer.json(204, null);
            if (s.path().endsWith("/test")) return Support.Answer.json(200, ping);
            // The first PUT with a url sets the store up: 201.
            return Support.Answer.json(s.method().equals("PUT") && s.body().contains("url") ? 201 : 200, view);
        })) {
            TouchqueClient tq = client(stub);
            assertEquals(view, tq.identity().getUserStore());
            assertEquals(view, tq.identity().setUserStore(STORE, null));
            tq.identity().setUserStore(null, false);
            tq.identity().setUserStore(null, null);
            assertEquals(ping, tq.identity().testUserStore(null));
            // An empty url tests the endpoint set, like null ({"url": ""} would be a 400).
            assertEquals(ping, tq.identity().testUserStore(""));
            tq.identity().testUserStore("https://staging.acme.test/user-store?v=2&n=ü#x");
            JsonNode removed = tq.identity().removeUserStore();
            assertTrue(removed.isObject() && removed.isEmpty());
            // Nothing set any more: still 204, so removing twice is fine.
            assertTrue(tq.identity().removeUserStore().isEmpty());
        }
        assertEquals(List.of("GET /identity/user-store", "PUT /identity/user-store", "PUT /identity/user-store", "PUT /identity/user-store",
                "POST /identity/user-store/test", "POST /identity/user-store/test", "POST /identity/user-store/test", "DELETE /identity/user-store",
                "DELETE /identity/user-store"), lines(seen));
        // A null argument is left out (the API keeps what is set); the url goes in the JSON body as given, never URL-encoded.
        assertEquals(List.of("", "{\"url\":\"" + STORE + "\"}", "{\"enabled\":false}", "{}", "{}", "{}", "{\"url\":\"https://staging.acme.test/user-store?v=2&n=ü#x\"}", "", ""),
                seen.stream().map(Support.Seen::body).toList());
        assertNull(seen.get(0).header("Content-Type"));
        assertEquals("application/json", seen.get(4).header("Content-Type"));
        assertEquals("application/json", seen.get(5).header("Content-Type"));
        assertNull(seen.get(7).header("Content-Type"));
    }

    @Test
    void userStoreRefusalsMapToTouchqueApiException() throws Exception {
        Map<String, Support.Answer> answers = Map.of(
                "PUT", Support.Answer.json(409, obj("{\"error\":\"passwords_off\",\"field\":\"enabled\",\"message\":\"Moving users in checks their passwords: turn passwords on first\"}")),
                "POST", Support.Answer.json(400, obj("{\"error\":\"invalid_request\",\"field\":\"url\",\"message\":\"url must use https\"}")),
                "DELETE", Support.Answer.json(404, obj("{\"error\":\"not_enabled\",\"message\":\"PUT /identity/tenant first\"}")),
                "GET", Support.Answer.json(403, obj("{\"error\":\"feature_read_only\",\"feature\":\"ciam\"}")));
        try (Support.Stub stub = new Support.Stub(s -> answers.get(s.method()))) {
            TouchqueClient tq = client(stub);
            TouchqueApiException off = assertThrows(TouchqueApiException.class, () -> tq.identity().setUserStore(STORE, true));
            assertEquals(List.of(409, "passwords_off", "enabled", "Moving users in checks their passwords: turn passwords on first"),
                    List.of(off.status(), off.error(), off.body().path("field").asText(), off.getMessage()));
            TouchqueApiException url = assertThrows(TouchqueApiException.class, () -> tq.identity().testUserStore("http://api.acme.test/x"));
            assertEquals(List.of(400, "invalid_request", "url", "url must use https"), List.of(url.status(), url.error(), url.body().path("field").asText(), url.getMessage()));
            // DELETE answers 204 even with nothing set: a 404 is Touchque Login not set up, never "already removed".
            TouchqueApiException notEnabled = assertThrows(TouchqueApiException.class, () -> tq.identity().removeUserStore());
            assertEquals(List.of(404, "not_enabled"), List.of(notEnabled.status(), notEnabled.error()));
            TouchqueFeatureReadOnlyException readOnly = assertThrows(TouchqueFeatureReadOnlyException.class, () -> tq.identity().getUserStore());
            assertEquals(List.of(403, "ciam"), List.of(readOnly.status(), readOnly.feature()));
        }
    }

    @Test
    void userStoreRequestsPassTheWebhookVerify() {
        Webhook webhook = new TouchqueClient(new TouchqueOptions().apiKey("tq_x").apiSecret(SECRET)).webhook();
        // The vectors carry a fixed past timestamp: no freshness check for them.
        ObjectNode q = webhook.verify(VERIFY_PASSWORD, VERIFY_PASSWORD_SIGNATURE, 0);
        assertEquals(List.of("user_store.verify_password", "acme", "zoe@acme.test", "pässwörd 🔑 \"1\" \\ € 😀 </x>\u2028"),
                List.of(q.path("event").asText(), q.path("tenant").asText(), q.path("email").asText(), q.path("password").asText()));
        // Without the header, the body's own signature.
        assertEquals("user_store.verify_password", Json.str(webhook.verify(VERIFY_PASSWORD, null, 0), "event"));
        assertEquals("zoe@acme.test", Json.str(webhook.verify(GET_USER, GET_USER_SIGNATURE, 0), "email"));
        assertEquals("user_store.ping", Json.str(webhook.verify(PING, PING_SIGNATURE, 0), "event"));
        String changed = VERIFY_PASSWORD.replace("pässwörd", "passwörd");
        assertThrows(TouchqueWebhookSignatureException.class, () -> webhook.verify(changed, VERIFY_PASSWORD_SIGNATURE, 0));
        Webhook otherWorkspace = new TouchqueClient(new TouchqueOptions().apiKey("tq_x").apiSecret("another_secret")).webhook();
        assertThrows(TouchqueWebhookSignatureException.class, () -> otherWorkspace.verify(PING, PING_SIGNATURE, 0));

        // A request of now passes the default 5-minute window, and once with a replay cache.
        String now = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC).format(Instant.now());
        ObjectNode payload = Json.object().put("event", "user_store.get_user").put("tenant", "acme").put("email", "zoe@acme.test")
                .put("timestamp", now).put("jti", "0d4c7f1e-5b3a-4f7e-9c21-6a8b9d0e1f2a");
        String signature = Crypto.hmacHex(SECRET, Webhook.canonicalize(Json.write(payload)));
        String fresh = Json.write(payload.put("signature", signature));
        assertEquals("user_store.get_user", Json.str(webhook.verify(fresh, signature), "event"));
        Webhook.MemoryReplayCache cache = new Webhook.MemoryReplayCache();
        webhook.verify(fresh, signature, Webhook.DEFAULT_TOLERANCE_SECONDS, cache);
        assertThrows(TouchqueWebhookReplayException.class, () -> webhook.verify(fresh, signature, Webhook.DEFAULT_TOLERANCE_SECONDS, cache));
    }
}
