package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.flow.Guard;
import com.touchque.internal.Json;
import com.touchque.resources.Assist;
import com.touchque.resources.LoginRequestOptions;
import com.touchque.resources.Mobile;
import com.touchque.resources.Recovery;
import com.touchque.resources.Risk;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Silent sign-ins, Never Locked Out, help desk, Mobile SDK and the Management API against the fake API. */
class ResourceTest {
    private static final String USER = "jane@acme.com";
    private static final List<String> SILENT_CODES = List.of("known_browser", "recent_approval", "same_phone", "familiar_network", "no_risk_signal");
    private final Support.FakeApi api = Support.FakeApi.get();
    private final String proof;
    private final String thumbprint;

    ResourceTest() {
        JsonNode vectors = Support.fixture("silent-sign-in-vectors.json").get("browserProof");
        String p = null;
        for (JsonNode c : vectors.get("cases")) {
            if ("validHeaderEncoding".equals(c.get("name").asText())) p = c.get("proof").asText();
        }
        proof = p;
        thumbprint = vectors.get("thumbprint").get("expected").asText();
    }

    @BeforeEach
    void reset() {
        api.reset();
        api.link(USER);
    }

    private List<String> paths() {
        List<String> out = new ArrayList<>();
        api.calls().forEach(c -> out.add(c.get("path").asText()));
        return out;
    }

    private List<JsonNode> loginRequests() {
        List<JsonNode> out = new ArrayList<>();
        api.calls().forEach(c -> {
            if ("/login/request".equals(c.get("path").asText())) out.add(c.get("body"));
        });
        return out;
    }

    private Guard.Input g(String browserProof, Guard.SilentSignIn silent, String action, String token) {
        return new Guard.Input(USER, action).ip("203.0.113.7").userAgent("UA").token(token).browserProof(browserProof).silentSignIn(silent);
    }

    private static List<String> codes(List<RiskReason> reasons) {
        return reasons.stream().map(RiskReason::code).toList();
    }

    @Test
    void riskCheckAsksForANewBrowserAndSendsNothingToThePhone() {
        TouchqueClient tq = api.client();
        Risk.CheckResult none = tq.risk().check(new Risk.CheckOptions(USER));
        assertEquals(List.of(true, "normal", "enforce", "CHK-2QX"), List.of(none.prompt(), none.assurance(), none.silentMode(), none.caseCode()));
        assertEquals(List.of("no_browser_key"), codes(none.reasons()));
        Risk.CheckResult res = tq.risk().check(new Risk.CheckOptions(USER).type("LOGIN").clientIp("203.0.113.7").userAgent("UA").browserProof(proof).maxAgeSeconds(3600));
        assertEquals(List.of(new RiskReason("new_browser", "This browser has not been approved on the phone for this account", null)), res.reasons());
        assertEquals(Json.toNode(Map.of("externalUsername", USER, "type", "LOGIN", "clientIp", "203.0.113.7", "userAgent", "UA", "browserProof", proof, "maxAgeSeconds", 3600)),
                api.get("/__test/last-check"));
        assertEquals(List.of("/risk/check", "/risk/check"), paths());
        assertThrows(TouchqueConfigException.class, () -> tq.risk().check(new Risk.CheckOptions(USER).maxAgeSeconds(-1)));

        api.opts(Map.of("silent", true));
        Risk.CheckResult silent = tq.risk().check(new Risk.CheckOptions(USER).browserProof(proof));
        assertFalse(silent.prompt());
        assertEquals(SILENT_CODES, codes(silent.reasons()));
        assertTrue(tq.risk().check(new Risk.CheckOptions(USER).type("SEND_MONEY").browserProof(proof)).prompt());
    }

    @Test
    void anApprovalMakesTheBrowserKnownUntilForgotten() {
        TouchqueClient tq = api.client();
        String first = tq.login().request(new LoginRequestOptions(USER).browserProof(proof)).requestId();
        assertEquals(proof, loginRequests().get(0).get("browserProof").asText());
        assertTrue(tq.risk().browsers(USER).isEmpty());
        api.approve(first);
        JsonNode browsers = tq.risk().browsers(USER);
        assertEquals(1, browsers.size());
        assertEquals(List.of(thumbprint, "push"), List.of(browsers.get(0).get("thumbprint").asText(), browsers.get(0).get("lastMfaMethod").asText()));
        assertNull(Json.str(browsers.get(0), "lastSilentAt"));
        List<String> urls = new ArrayList<>();
        api.calls().forEach(c -> urls.add(c.get("url").asText()));
        assertTrue(urls.contains("/risk/browsers?externalUsername=jane%40acme.com"));
        assertEquals(0, tq.risk().forgetBrowsers(USER, "other"));
        assertEquals(1, tq.risk().forgetBrowsers(USER, thumbprint));
        assertTrue(tq.risk().browsers(USER).isEmpty());
    }

    @Test
    void aKnownBrowserWithNothingNewIsApprovedAtOnceWithNoPush() {
        api.opts(Map.of("silent", true));
        Guard.Result res = Guard.run(api.client(), g(proof, Guard.SilentSignIn.on(), "LOGIN", null));
        assertEquals(200, res.status());
        assertEquals(List.of("silent", USER, "LOGIN", "SILENT", "silent"),
                List.of(res.approved().requestId(), res.approved().user(), res.approved().action(), res.approved().confirmedVia(), res.approved().assurance().method()));
        assertEquals(SILENT_CODES, codes(res.approved().reasons()));
        assertEquals(List.of("/risk/check"), paths());
    }

    @Test
    void otherwiseThePushStartsWithTheProofAndPollsNeverAskAgain() {
        TouchqueClient tq = api.client();
        Guard.Result first = Guard.run(tq, g(proof, Guard.SilentSignIn.on(), "LOGIN", null));
        assertEquals(202, first.status());
        assertEquals(List.of("/risk/check", "/login/request"), paths());
        api.opts(Map.of("silent", true));
        String token = first.body().get("token").asText();
        assertEquals("waiting", Guard.run(tq, g(proof, Guard.SilentSignIn.on(), "LOGIN", token)).body().get("touchque").get("state").asText());
        assertEquals(1, paths().stream().filter("/risk/check"::equals).count());
        api.approve(null);
        Guard.Result done = Guard.run(tq, g(proof, Guard.SilentSignIn.on(), "LOGIN", token));
        assertEquals(List.of("DEVICE", "push"), List.of(done.approved().confirmedVia(), done.approved().assurance().method()));
        assertNull(done.approved().reasons());
    }

    @Test
    void silentSignInFailsClosedAndIsOffByDefault() throws Exception {
        api.opts(Map.of("silent", true));
        TouchqueClient tq = api.client();
        JsonNode critical = Guard.run(tq, g(proof, Guard.SilentSignIn.on(), "SEND_MONEY", null)).body().get("touchque");
        assertEquals(List.of("waiting", "47"), List.of(critical.get("state").asText(), critical.get("number").asText()));
        api.reset();
        api.link(USER);
        api.opts(Map.of("silent", true));
        assertEquals(202, Guard.run(tq, g(proof, null, "LOGIN", null)).status());
        assertEquals(proof, loginRequests().get(0).get("browserProof").asText());
        assertEquals(202, Guard.run(tq, g("x".repeat(5000), Guard.SilentSignIn.on(), "LOGIN", null)).status());
        assertNull(loginRequests().get(1).get("browserProof"));
        assertFalse(paths().contains("/risk/check"));
        Guard.run(tq, g(proof, new Guard.SilentSignIn(0), "LOGIN", null));
        assertEquals(0, api.get("/__test/last-check").get("maxAgeSeconds").asInt());

        // Anything but prompt: false (or an error) starts the push.
        List<JsonNode> answers = new ArrayList<>(List.of(Json.object().put("prompt", "false"), Json.object().put("prompt", 0), Json.object()));
        answers.add(null);
        for (JsonNode answer : answers) {
            try (Support.Stub stub = new Support.Stub(seen -> seen.path().startsWith("/risk/check")
                    ? (answer == null ? Support.Answer.json(500, Map.of("error", "boom")) : Support.Answer.json(200, answer))
                    : Support.Answer.json(200, Map.of("requestId", "r1", "expiresAt", "soon")))) {
                TouchqueClient stubbed = new TouchqueClient(new TouchqueOptions().apiKey("tq_x").apiSecret("s").baseUrl(stub.baseUrl));
                assertEquals(202, Guard.run(stubbed, g(proof, Guard.SilentSignIn.on(), "LOGIN", null)).status());
            }
        }
    }

    @Test
    void neverLockedOut() {
        for (String u : List.of("ada@acme.com", "bo@acme.com", "cy@acme.com")) api.link(u);
        TouchqueClient tq = api.client();
        JsonNode out1 = tq.recovery().setVouchers("ada@acme.com", List.of("bo@acme.com", "zed@acme.com"));
        assertTrue(out1.get("vouchers").get(0).get("eligible").asBoolean());
        assertEquals(List.of(false, "no_phone"), List.of(out1.get("vouchers").get(1).get("eligible").asBoolean(), out1.get("vouchers").get(1).get("reason").asText()));
        assertEquals("bo@acme.com", tq.recovery().vouchers("ada@acme.com").get("vouchers").get(0).get("externalUsername").asText());

        TouchqueApiException e = assertThrows(TouchqueApiException.class, () -> tq.recovery().start(new Recovery.StartOptions("cy@acme.com")));
        assertEquals(List.of(409, "not_enough_vouchers"), List.of(e.status(), e.code()));

        tq.recovery().setVouchers("ada@acme.com", List.of("bo@acme.com", "cy@acme.com"));
        JsonNode r = tq.recovery().start(new Recovery.StartOptions("ada@acme.com").clientIp("203.0.113.7").displayName("Ada").coolOffMinutes(90));
        assertEquals("AWAITING_DEVICE", r.get("status").asText());
        assertTrue(r.get("bindUri").asText().startsWith("touchque://recover?id="));
        assertEquals(Json.toNode(Map.of("externalUsername", "ada@acme.com", "clientIp", "203.0.113.7", "displayName", "Ada", "coolOffMinutes", 90)), api.lastCall().get("body"));
        String id = r.get("recoveryId").asText();
        api.post("/__test/recovery", Map.of("to", "VOUCHING"));
        JsonNode now = tq.recovery().status(id);
        assertEquals(List.of("11", "12"), List.of(now.get("vouchers").get(0).get("code").asText(), now.get("vouchers").get(1).get("code").asText()));
        assertTrue(Recovery.isOpen(now));
        assertEquals(id, tq.recovery().list(null, true).get(0).get("recoveryId").asText());
        JsonNode vetoed = tq.recovery().veto(id, "admin@acme.com", null);
        assertEquals(List.of("VETOED", "admin@acme.com"), List.of(vetoed.get("status").asText(), vetoed.get("endedBy").asText()));
        assertTrue(tq.recovery().list(null, true).isEmpty());
        assertEquals(id, tq.recovery().list("ada@acme.com", false).get(0).get("recoveryId").asText());

        api.reset();
        assertThrows(TouchqueConfigException.class, () -> tq.recovery().start(new Recovery.StartOptions("")));
        assertThrows(TouchqueConfigException.class, () -> tq.recovery().status(""));
        assertThrows(TouchqueConfigException.class, () -> tq.recovery().list(null, false));
        assertTrue(api.calls().isEmpty());
    }

    @Test
    void helpDesk() {
        api.link("ayse@acme.com");
        TouchqueClient tq = api.client();
        JsonNode s = tq.assist().open("ayse@acme.com", new Assist.Agent("Deniz Kaya", "IT help desk", null), "Ticket 4411");
        assertEquals(List.of("OPEN", true, true), List.of(s.get("status").asText(), s.get("notified").asBoolean(), s.get("phone").asBoolean()));
        String id = s.get("id").asText();
        JsonNode check = tq.assist().verify(id, "reset_2fa", "reset your two-step verification", null);
        assertTrue(check.get("challengeCode").asText().matches("^[0-9]{2}$"));
        String rid = check.get("requestId").asText();
        api.post("/__test/assist", Map.of("requestId", rid, "action", "approve"));
        assertTrue(Assist.checkPassed(tq.assist().get(id), rid));
        assertEquals(428, assertThrows(TouchqueApiException.class, () -> tq.assist().spend(id, rid, "reset_password")).status());
        assertFalse(Assist.checkPassed(tq.assist().spend(id, rid, "reset_2fa"), rid));
        assertEquals(id, tq.assist().list("ayse@acme.com", false).get(0).get("id").asText());

        JsonNode notMe = tq.assist().verify(id, "activation_link", null, null);
        api.post("/__test/assist", Map.of("requestId", notMe.get("requestId").asText(), "action", "not_me"));
        assertTrue(tq.assist().get(id).get("frozen").asBoolean());
        JsonNode unlock = tq.assist().verify(id, "unlock", null, null);
        api.post("/__test/assist", Map.of("requestId", unlock.get("requestId").asText(), "action", "approve"));
        JsonNode unfrozen = tq.assist().unfreeze(id, unlock.get("requestId").asText());
        assertEquals(List.of(true, false), List.of(unfrozen.get("unfrozen").asBoolean(), unfrozen.get("session").get("frozen").asBoolean()));
        assertEquals("ENDED", tq.assist().end(id, null, null).get("status").asText());
        assertEquals("assist_not_open", assertThrows(TouchqueApiException.class, () -> tq.assist().verify(id, "unlock", null, null)).code());

        tq.auth().generateSecret("can@acme.com");
        JsonNode noPhone = tq.assist().open("can@acme.com", Assist.Agent.of("Deniz Kaya"), null, null, false);
        assertFalse(noPhone.get("phone").asBoolean());
        TouchqueApiException e = assertThrows(TouchqueApiException.class, () -> tq.assist().verify(noPhone.get("id").asText(), "new_phone", null, null));
        assertEquals(List.of("no_phone", "never_locked_out"), List.of(e.code(), e.route()));
        assertThrows(TouchqueConfigException.class, () -> tq.assist().list(null, false));
    }

    @Test
    void mobileSdkServerSide() {
        TouchqueClient tq = api.client();
        JsonNode first = tq.mobile().createEnrollment("ada@shop.example", false, null);
        assertTrue(first.get("enrollmentToken").asText().matches("^tqe_[A-Za-z0-9_-]{43}$"));
        JsonNode device = api.post("/__test/mobile-enroll", Map.of("enrollmentToken", first.get("enrollmentToken").asText(), "platform", "android"));
        assertEquals("already_enrolled", assertThrows(TouchqueApiException.class, () -> tq.mobile().createEnrollment("ada@shop.example", false, null)).code());
        JsonNode second = tq.mobile().createEnrollment("ada@shop.example", true, 300);
        assertEquals(device.get("deviceId").asText(), second.get("replacesDeviceId").asText());
        api.post("/__test/mobile-enroll", Map.of("enrollmentToken", second.get("enrollmentToken").asText()));
        JsonNode active = tq.mobile().listDevices("ada@shop.example", null, null, null).get("devices");
        assertEquals(1, active.size());
        assertEquals("ios", active.get(0).get("platform").asText());
        assertEquals("replaced", tq.mobile().getDevice(device.get("deviceId").asText()).get("revokedReason").asText());
        String deviceId = active.get(0).get("deviceId").asText();
        JsonNode push = tq.mobile().testPush(deviceId);
        assertEquals(List.of("webhook", true), List.of(push.get("via").asText(), push.get("ok").asBoolean()));
        assertEquals(Json.parse("{\"removed\":true,\"wasLinked\":true}"), tq.mobile().removeDevice(deviceId));

        assertEquals("optional", tq.mobile().settings().get("attestation").asText());
        JsonNode s = tq.mobile().updateSettings(Map.of("iosAppIds", List.of("ABCDE12345.com.shop.app"), "attestation", "required"));
        assertEquals(Json.parse("[\"ABCDE12345.com.shop.app\"]"), s.get("iosAppIds"));
        assertEquals(600, s.get("enrollTtlSeconds").asInt());
        s = tq.mobile().updateSettings(Map.of(
                "apns", Map.of("keyId", "ABC123DEFG", "teamId", "TEAM123456", "topic", "com.shop.app", "key", "-----BEGIN PRIVATE KEY-----"),
                "fcm", Map.of("serviceAccount", Map.of("project_id", "shop", "client_email", "push@shop.iam.gserviceaccount.com", "private_key", "x"))));
        assertEquals(List.of("touchque", "shop", "push@shop.iam.gserviceaccount.com"),
                List.of(s.get("push").get("ios").asText(), s.get("push").get("fcm").get("projectId").asText(), s.get("push").get("fcm").get("clientEmail").asText()));
        Map<String, Object> clear = new HashMap<>();
        clear.put("apns", null);
        assertEquals("webhook", tq.mobile().updateSettings(clear).get("push").get("ios").asText());
        assertThrows(TouchqueConfigException.class, () -> tq.mobile().updateSettings(Map.of("nope", 1)));
    }

    @Test
    void mobilePushWebhookBecomesTheApnsPayloadAndFcmData() {
        ObjectNode e = Json.parseObject("{\"event\":\"MOBILE_PUSH\",\"externalUsername\":\"ada@shop.example\",\"deviceId\":\"d1\",\"platform\":\"ios\",\"pushToken\":\"apns-token\","
                + "\"kind\":\"approval\",\"requestId\":\"r1\",\"expiresAt\":\"2026-10-26T10:00:30.000Z\","
                + "\"alert\":{\"title\":\"Change delivery address\",\"body\":\"Demo Shop is waiting for your approval.\"},"
                + "\"data\":{\"touchque\":\"{\\\"v\\\":1,\\\"k\\\":\\\"approval\\\",\\\"did\\\":\\\"d1\\\",\\\"rid\\\":\\\"r1\\\"}\"}}");
        Mobile.Push push = Mobile.pushFromWebhook(e);
        ObjectNode aps = Json.object().put("sound", "default").put("interruption-level", "time-sensitive");
        aps.set("alert", e.get("alert").deepCopy());
        ObjectNode apns = Json.object();
        apns.set("aps", aps);
        apns.put("touchque", e.get("data").get("touchque").asText());
        assertEquals(apns, push.apns());
        assertEquals(e.get("data").get("touchque").asText(), push.fcmData().get("touchque"));
        assertNull(Mobile.pushFromWebhook(Json.object().put("event", "DEVICE_LINKED")));
        assertTrue(push.isExpired(Instant.parse("2026-10-26T10:01:00Z")));
        assertFalse(push.isExpired(Instant.parse("2026-10-26T10:00:00Z")));
    }

    @Test
    void managementApiCalls() {
        TouchqueClient tq = api.client();
        api.reset();
        tq.identity().users().list(Map.of("q", "ayse", "limit", 10));
        tq.identity().users().create(Map.of("email", "a@x.com", "passwordHash", "$2b$10$abc"));
        Map<String, Object> plan = new HashMap<>();
        plan.put("plan", null);
        tq.identity().users().update("usr_1", Map.of("appMetadata", plan));
        tq.identity().users().block("usr_1", "fraud");
        tq.identity().users().delete("usr_1");
        tq.identity().users().resetMfa("usr_1");
        tq.identity().users().passwordReset("usr_1", false, null);
        tq.identity().users().addRoles("usr_1", List.of("rol_1"), "org_1");
        tq.identity().users().removeRole("usr_1", "rol_1", "org_1");
        tq.identity().imports().start(Map.of("users", List.of(Map.of("email", "b@x.com")), "upsert", true));
        tq.identity().organizations().invite("org_1", Map.of("email", "c@x.com", "clientId", "cli", "roleIds", List.of("rol_1")));
        assertTrue(tq.identity().roles().list().isEmpty());
        tq.identity().updateTenant(Map.of("slug", "acme", "displayName", "Acme"));
        assertEquals("done", tq.identity().exports().waitFor("job_1", Duration.ofMillis(1), Duration.ofMillis(1)).get("status").asText());
        tq.identity().setDelivery("email", Map.of("provider", "postmark", "from", "login@acme.test", "serverToken", "pm"));
        tq.identity().testDelivery("sms", "+905321234567");
        tq.identity().setAttackProtection(Map.of("bot", Map.of("provider", "turnstile", "siteKey", "k", "secret", "s", "mode", "risky")));
        tq.identity().clients().rotateSecret("cli_1");
        tq.identity().users().endSession("usr_1", "ses_1");
        assertTrue(tq.identity().exports().file("job_1").contains("ok"));
        tq.identity().setApproverAppName("Acme Pay");
        tq.identity().setCustomDomainOnly(true);
        tq.identity().checkDomainCertificate("dom_1");

        List<JsonNode> calls = new ArrayList<>();
        api.calls().forEach(c -> {
            if (c.get("path").asText().startsWith("/identity")) calls.add(c);
        });
        assertEquals(List.of("GET /identity/users?limit=10&q=ayse", "POST /identity/users", "PATCH /identity/users/usr_1", "POST /identity/users/usr_1/block",
                "DELETE /identity/users/usr_1", "DELETE /identity/users/usr_1/mfa", "POST /identity/users/usr_1/password-reset", "POST /identity/users/usr_1/roles",
                "DELETE /identity/users/usr_1/roles/rol_1?organizationId=org_1", "POST /identity/users-imports", "POST /identity/organizations/org_1/invitations",
                "GET /identity/roles", "PUT /identity/tenant", "GET /identity/users-exports/job_1", "PUT /identity/delivery/email", "POST /identity/delivery/sms/test",
                "PUT /identity/attack-protection", "POST /identity/clients/cli_1/rotate-secret", "DELETE /identity/users/usr_1/sessions/ses_1",
                "GET /identity/users-exports/job_1/file", "PUT /identity/tenant", "PUT /identity/tenant", "POST /identity/custom-domains/dom_1/check-certificate"),
                calls.stream().map(c -> c.get("method").asText() + " " + c.get("url").asText()).toList());
        assertEquals(Json.parse("{\"branding\":{\"approverAppName\":\"Acme Pay\"}}"), calls.get(20).get("body"));
        assertEquals(Json.parse("{\"customDomainOnly\":true}"), calls.get(21).get("body"));
        assertEquals(Json.parse("{\"email\":\"a@x.com\",\"passwordHash\":\"$2b$10$abc\"}"), calls.get(1).get("body"));
        assertEquals(Json.parse("{\"appMetadata\":{\"plan\":null}}"), calls.get(2).get("body"));
        assertEquals(Json.parse("{\"roleIds\":[\"rol_1\"],\"organizationId\":\"org_1\"}"), calls.get(7).get("body"));
    }

    @Test
    void passkeyBackendCalls() {
        TouchqueClient tq = api.client();
        api.link("pk@acme.com");
        TouchqueApiException e = assertThrows(TouchqueApiException.class, () -> tq.webauthn().registerOptions("pk@acme.com", true, null));
        assertEquals(List.of(403, "enrollment_approval_required"), List.of(e.status(), e.code()));
        assertTrue(tq.webauthn().listCredentials("pk@acme.com").isEmpty());
        tq.webauthn().deleteCredential("cred 1", "pk@acme.com");
        assertEquals("/webauthn/credentials/cred%201?externalUsername=pk%40acme.com", api.lastCall().get("url").asText());
        JsonNode availability = tq.webauthn().primaryAvailability();
        assertTrue(availability.get("enabled").asBoolean());
        assertEquals("preferred", availability.get("userVerification").asText());
    }
}
