package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.flow.Approval;
import com.touchque.flow.CompleteExpectations;
import com.touchque.flow.Guard;
import com.touchque.flow.StartOptions;
import com.touchque.flow.Step;
import com.touchque.flow.Steps;
import com.touchque.internal.Json;
import com.touchque.relay.RelayHandler;
import com.touchque.relay.RelayOptions;
import com.touchque.relay.RelayRequest;
import com.touchque.relay.RelayResponse;
import com.touchque.resources.ActionTypes;
import com.touchque.resources.Login;
import com.touchque.resources.LoginRequestOptions;
import com.touchque.resources.QrPairings;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Against the shared fake Touchque API: a real HTTP round trip, so request signing is verified
 * too. Same scenarios as the Node/Python/PHP/Go/.NET/Ruby step-up tests.
 */
class ContractTest {
    private static final String THUMB = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    private final Support.FakeApi api = Support.FakeApi.get();

    @BeforeEach
    void reset() {
        api.reset();
    }

    private static Guard.Input g(String user, String token) {
        return new Guard.Input(user, "LOGIN").token(token);
    }

    private static JsonNode step(Guard.Result r) {
        return r.body().get("touchque");
    }

    private static String token(Guard.Result r) {
        return r.body().get("token").asText();
    }

    @Test
    void loginRequestStatusAndReportFraud() {
        api.link("ada@acme.com");
        TouchqueClient tq = api.client();
        Login.RequestResult sent = tq.login().request(new LoginRequestOptions("ada@acme.com").type("LOGIN").clientIp("203.0.113.7").userAgent("UA")
                .details(List.of(LoginDetail.of("Amount", "250 EUR"))).challengeDigits(3).expiresIn(120).locale("en"));
        assertEquals("K7P-2QX", sent.caseCode());
        assertEquals(Json.parse("{\"externalUsername\":\"ada@acme.com\",\"type\":\"LOGIN\",\"clientIp\":\"203.0.113.7\",\"userAgent\":\"UA\",\"challengeDigits\":3,"
                + "\"expiresIn\":120,\"details\":[{\"label\":\"Amount\",\"value\":\"250 EUR\"}],\"locale\":\"en\"}"), api.lastCall().get("body"));
        assertEquals("PENDING", tq.login().status(sent.requestId()).status());
        api.approve(sent.requestId());
        Login.Status status = tq.login().status(sent.requestId());
        assertEquals(List.of("CONFIRMED", "push"), List.of(status.status(), status.assurance().method()));

        JsonNode report = tq.login().reportFraud(sent.requestId(), "chargeback", "card holder disputed it");
        assertTrue(report.get("reported").asBoolean() && !report.get("alreadyReported").asBoolean());
        assertTrue(tq.login().reportFraud(sent.requestId(), null, null).get("alreadyReported").asBoolean());
        assertThrows(TouchqueConfigException.class, () -> tq.login().reportFraud("", null, null));
    }

    @Test
    void verifyRunsOnChallengeBeforeTheWaitAndThrowsOnRejection() {
        api.link("bo@acme.com");
        api.opts(Map.of("numberMatch", true));
        TouchqueClient tq = api.client();
        AtomicReference<Login.VerifyChallenge> seen = new AtomicReference<>();
        Login.VerifyResult result = tq.login().verify(new LoginRequestOptions("bo@acme.com").timeout(Duration.ofSeconds(10)).onChallenge(c -> {
            seen.set(c);
            api.approve(c.requestId());
        }));
        assertTrue(result.approved());
        assertEquals("47", seen.get().challengeCode());
        assertEquals("K7P-2QX", seen.get().caseCode());
        assertTrue(seen.get().reasons().stream().anyMatch(r -> r.code().equals("number_match_requested")));

        assertThrows(TouchqueRejectedException.class, () -> tq.login().verify(new LoginRequestOptions("bo@acme.com").onChallenge(c -> api.reject(c.requestId()))));

        api.opts(Map.of("passkeyOnly", true));
        assertEquals("policy", assertThrows(TouchquePasskeyRequiredException.class, () -> tq.login().verify("bo@acme.com")).reason());
        api.opts(Map.of("passkeyOnly", false));
        TouchquePasskeyRequiredException escalated = assertThrows(TouchquePasskeyRequiredException.class,
                () -> tq.login().verify(new LoginRequestOptions("bo@acme.com").onChallenge(c -> api.escalate(c.requestId()))));
        assertEquals("step_up", escalated.reason());
        assertThrows(TouchqueTimeoutException.class, () -> tq.login().verify(new LoginRequestOptions("bo@acme.com").timeout(Duration.ofMillis(500))));
    }

    @Test
    void unlinkedUserIsAClearApiError() {
        TouchqueApiException e = assertThrows(TouchqueApiException.class, () -> api.client().login().request("nobody@acme.com"));
        assertEquals(List.of(404, "device_not_linked"), List.of(e.status(), e.code()));
    }

    @Test
    void startCheckCompleteFullFlow() {
        api.link("jane@acme.com");
        TouchqueClient tq = api.client();
        Step step = tq.start("SEND_MONEY", new StartOptions("jane@acme.com").details(List.of(LoginDetail.of(" Amount ", "250 EUR"))).referenceId("tx-9"));
        assertEquals(List.of("waiting", "47"), List.of(step.state(), step.number()));
        assertEquals(List.of(LoginDetail.of("Amount", "250 EUR")), step.details());
        assertEquals("waiting", tq.check(step.requestId()).state());
        api.approve(null);
        assertEquals("approved", tq.check(step.requestId()).state());
        CompleteExpectations expect = new CompleteExpectations("Jane@acme.com", "SEND_MONEY", List.of(LoginDetail.of("Amount", "250 EUR")), "tx-9");
        Approval approval = tq.complete(step.requestId(), expect);
        assertEquals("push", approval.assurance().method());
        assertFalse(approval.assurance().phishingResistant());
        assertEquals("already_used", assertThrows(TouchqueApiException.class, () -> tq.complete(step.requestId(), expect)).code());
    }

    @Test
    void completeRefusesADifferentAmountAndUnknownActionsAreConfigErrors() {
        api.link("jane2@acme.com");
        TouchqueClient tq = api.client();
        Step step = tq.start("SEND_MONEY", new StartOptions("jane2@acme.com").details(List.of(LoginDetail.of("Amount", "250 EUR"))));
        api.approve(step.requestId());
        assertThrows(TouchqueApprovalMismatchException.class,
                () -> tq.complete(step.requestId(), new CompleteExpectations("jane2@acme.com", "SEND_MONEY", List.of(LoginDetail.of("Amount", "9999 EUR")), null)));
        TouchqueConfigException e = assertThrows(TouchqueConfigException.class, () -> tq.start("NOT_DEFINED", new StartOptions("jane2@acme.com")));
        assertTrue(e.getMessage().contains("NOT_DEFINED"));
    }

    @Test
    void anEmptyReferenceIdIsTheSameAsNone() {
        api.link("jane3@acme.com");
        TouchqueClient tq = api.client();
        Step step = tq.start("SEND_MONEY", new StartOptions("jane3@acme.com").referenceId(""));
        api.approve(step.requestId());
        assertEquals("jane3@acme.com", tq.complete(step.requestId(), new CompleteExpectations("jane3@acme.com", "SEND_MONEY", null, "")).user());

        Guard.Result first = Guard.run(tq, new Guard.Input("jane3@acme.com", "SEND_MONEY").referenceId(""));
        api.approve(null);
        assertEquals(200, Guard.run(tq, new Guard.Input("jane3@acme.com", "SEND_MONEY").referenceId("").token(token(first))).status());
    }

    @Test
    void aMismatchAfterTheApprovalIsA503NotAnException() throws Exception {
        try (Support.Stub stub = new Support.Stub(seen -> Support.Answer.json(200, seen.path().startsWith("/login/status/")
                ? Map.of("status", "CONFIRMED", "externalUsername", "mallory@acme.com", "type", "LOGIN")
                : Map.of("consumed", true, "externalUsername", "mallory@acme.com", "type", "LOGIN")))) {
            TouchqueClient tq = new TouchqueClient(new TouchqueOptions().apiKey("tq_test_key").apiSecret("test_secret").baseUrl(stub.baseUrl));
            ObjectNode claims = Json.object().put("u", "jane@acme.com").put("a", "LOGIN").put("d", "").put("st", "waiting").put("rid", "r-1")
                    .put("exp", System.currentTimeMillis() + 60_000);
            Guard.Result r = Guard.run(tq, g("jane@acme.com", Steps.signGuardToken("test_secret", claims)));
            assertEquals(503, r.status());
            assertEquals("unavailable", step(r).get("reason").asText());
        }
    }

    @Test
    void relayLowercasesUsernamesTheSameWayInATurkishLocale() {
        Locale before = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("tr-TR"));
        try {
            api.link("ilker@acme.com");
            RelayHandler<String> relay = new RelayHandler<>(api.client(), new RelayOptions<String>(req -> null).getLoginUser(req -> req));
            RelayResponse res = relay.handle(new RelayRequest<>("POST", "/login", Json.object(), "203.0.113.7", "UA", h -> null, "Ilker@acme.com"));
            assertEquals(202, res.status());
            assertEquals("waiting", res.body().get("touchque").get("state").asText());
            assertEquals("ilker@acme.com", api.lastCall().get("body").get("externalUsername").asText());
        } finally {
            Locale.setDefault(before);
        }
    }

    @Test
    void actionTypesDefine() {
        TouchqueClient tq = api.client();
        JsonNode t = tq.actionTypes().define("EXPORT", "Export data", null, true, new ActionTypes.SecondThought(List.of("safe_account"), "en"));
        assertTrue(t.get("critical").asBoolean());
        assertEquals(Json.parse("{\"type\":\"EXPORT\",\"name\":\"Export data\",\"critical\":true,\"secondThought\":{\"questions\":[\"safe_account\"],\"locale\":\"en\"}}"),
                api.lastCall().get("body"));
        boolean found = false;
        for (JsonNode x : tq.actionTypes().list()) found |= "EXPORT".equals(Json.str(x, "type"));
        assertTrue(found);
    }

    @Test
    void guardFullFlow() {
        api.link("guard@acme.com");
        api.opts(Map.of("numberMatch", true));
        TouchqueClient tq = api.client();
        Guard.Result first = Guard.run(tq, g("guard@acme.com", null));
        assertEquals(202, first.status());
        assertEquals(List.of("waiting", "47"), List.of(step(first).get("state").asText(), step(first).get("number").asText()));
        assertEquals(202, Guard.run(tq, g("guard@acme.com", token(first))).status());
        assertTrue(Guard.isStatusPoll(tq, g("guard@acme.com", token(first))));
        api.approve(null);
        Guard.Result done = Guard.run(tq, g("guard@acme.com", token(first)));
        assertEquals(200, done.status());
        assertEquals("push", done.approved().assurance().method());
        Guard.Result replay = Guard.run(tq, g("guard@acme.com", token(first)));
        assertNull(replay.approved());
        assertTrue(List.of(403, 408, 409).contains(replay.status()));
        // A token is bound to its user and action.
        Guard.Result other = Guard.run(tq, new Guard.Input("guard@acme.com", "SEND_MONEY").token(token(first)));
        assertEquals("waiting", step(other).get("state").asText());
        assertEquals(401, Guard.run(tq, new Guard.Input(null, "LOGIN")).status());
    }

    @Test
    void guardEnrollThenOfflineCode() {
        TouchqueClient tq = api.client();
        Guard.Result first = Guard.run(tq, g("new-offline@acme.com", null));
        assertEquals("enroll", step(first).get("state").asText());
        assertTrue(step(first).get("enroll").get("qrCodeDataUrl").asText().startsWith("data:image/png;base64,"));
        api.link("new-offline@acme.com");
        Guard.Result waiting = Guard.run(tq, g("new-offline@acme.com", token(first)));
        assertEquals("waiting", step(waiting).get("state").asText());
        Guard.Result off = Guard.run(tq, g("new-offline@acme.com", token(waiting)).offline(true));
        assertEquals("offline", step(off).get("state").asText());
        assertEquals("data:image/png;base64,OFFLINE", step(off).get("offline").get("qrDataUrl").asText());
        Guard.Result wrong = Guard.run(tq, g("new-offline@acme.com", token(off)).code("ZZZZ999"));
        assertEquals(4, step(wrong).get("offline").get("attemptsLeft").asInt());
        Guard.Result ok = Guard.run(tq, g("new-offline@acme.com", token(wrong)).code("ABCD123"));
        assertEquals(200, ok.status());
        assertEquals(List.of("offline_code", "OFFLINE_CODE"), List.of(ok.approved().assurance().method(), ok.approved().confirmedVia()));
    }

    @Test
    void guardKeepsTheFirstTimeQrWhileItIsUp() {
        TouchqueClient tq = api.client();
        Guard.Result first = Guard.run(tq, g("qr@acme.com", null));
        JsonNode enroll = step(first).get("enroll");
        assertEquals("data:image/png;base64,QR-qr@acme.com", enroll.get("qrCodeDataUrl").asText());
        String expiresAt = enroll.get("expiresAt").asText();
        long ee = Instant.parse(expiresAt).toEpochMilli();
        assertTrue(Math.abs(ee - (System.currentTimeMillis() + 300_000)) < 30_000, expiresAt);   // the API's 5 minutes
        assertEquals(ee, Steps.verifyGuardToken("test_secret", token(first)).get("ee").asLong());
        assertTrue(Guard.isStatusPoll(tq, g("qr@acme.com", token(first))));
        assertFalse(Guard.isStatusPoll(tq, g("eve@acme.com", token(first))));

        // A poll reads the link state only: the page keeps the QR and recovery codes it shows.
        int before = api.calls().size();
        Guard.Result poll = Guard.run(tq, g("qr@acme.com", token(first)));
        assertEquals(202, poll.status());
        assertEquals(Json.object().put("state", "enroll").put("expiresAt", expiresAt), step(poll));
        ArrayNode calls = api.calls();
        assertEquals(before + 1, calls.size());
        assertEquals(List.of("GET", "/users/qr%40acme.com"), List.of(calls.get(before).get("method").asText(), calls.get(before).get("path").asText()));
        ObjectNode claims = Steps.verifyGuardToken("test_secret", token(poll));
        assertEquals(List.of("enroll", ee), List.of(claims.get("st").asText(), claims.get("ee").asLong()));
        Guard.Result again = Guard.run(tq, g("qr@acme.com", token(poll)));
        assertEquals(Json.object().put("state", "enroll").put("expiresAt", expiresAt), step(again));

        // Linked: the push starts.
        api.link("qr@acme.com");
        Guard.Result waiting = Guard.run(tq, g("qr@acme.com", token(again)));
        assertEquals(List.of(202, "waiting"), List.of(waiting.status(), step(waiting).get("state").asText()));
        api.approve(null);
        assertEquals(200, Guard.run(tq, g("qr@acme.com", token(waiting))).status());
    }

    @Test
    void aFirstTimeQrAboutToExpireOrGoneIsReplaced() {
        TouchqueClient tq = api.client();
        // A QR within 15 s of its expiry is replaced: a new one, with new recovery codes.
        api.opts(Map.of("secretTtlMs", 10_000));
        Guard.Result first = Guard.run(tq, g("short@acme.com", null));
        assertEquals("data:image/png;base64,QR-short@acme.com", step(first).get("enroll").get("qrCodeDataUrl").asText());
        // The poll that renews it is not a status poll: relays count it against the user's limit.
        assertFalse(Guard.isStatusPoll(tq, g("short@acme.com", token(first))));
        Guard.Result next = Guard.run(tq, g("short@acme.com", token(first)));
        assertEquals("data:image/png;base64,QR2-short@acme.com", step(next).get("enroll").get("qrCodeDataUrl").asText());
        assertEquals("r2", step(next).get("enroll").get("recoveryCodes").get(0).asText());
        assertEquals("/auth/secret/reset", api.lastCall().get("path").asText());

        // Touchque no longer knows the user (404): the QR is gone, a new one.
        api.opts(Map.of("secretTtlMs", 300_000));
        Guard.Result fresh = Guard.run(tq, g("gone@acme.com", null));
        api.reset();
        Guard.Result renewed = Guard.run(tq, g("gone@acme.com", token(fresh)));
        assertEquals("data:image/png;base64,QR-gone@acme.com", step(renewed).get("enroll").get("qrCodeDataUrl").asText());
        assertEquals("/auth/generate-secret", api.lastCall().get("path").asText());

        // A 5.0 token (no ee): every poll starts again, as before.
        ObjectNode old = Json.object().put("u", "old@acme.com").put("a", "LOGIN").put("d", "").putNull("r").put("st", "enroll")
                .put("exp", System.currentTimeMillis() + 60_000);
        Guard.run(tq, g("old@acme.com", null));
        assertFalse(Guard.isStatusPoll(tq, g("old@acme.com", Steps.signGuardToken("test_secret", old))));
        Guard.Result restarted = Guard.run(tq, g("old@acme.com", Steps.signGuardToken("test_secret", old)));
        assertEquals("data:image/png;base64,QR2-old@acme.com", step(restarted).get("enroll").get("qrCodeDataUrl").asText());

        // A status poll only while the QR is up: a replayed token of an expired QR counts against the limit.
        long now = System.currentTimeMillis();
        assertTrue(Guard.isStatusPoll(tq, g("old@acme.com", Steps.signGuardToken("test_secret", old.deepCopy().put("ee", now + 60_000)))));
        assertFalse(Guard.isStatusPoll(tq, g("old@acme.com", Steps.signGuardToken("test_secret", old.deepCopy().put("ee", now + 10_000)))));
        assertFalse(Guard.isStatusPoll(tq, g("old@acme.com", Steps.signGuardToken("test_secret", old.deepCopy().put("ee", now - 1_000)))));
    }

    @Test
    void beforeStartRunsOnceBeforeAFirstTimeQrPollStartsAnythingAndItsAnswerWins() {
        TouchqueClient tq = api.client();
        AtomicInteger calls = new AtomicInteger();
        Guard.Result stop = new Guard.Result(429, null, Json.object().put("error", "RATE_LIMITED"), Step.of("rate_limited").withRetryAfter(7));
        Supplier<Optional<Guard.Result>> charge = () -> {
            calls.incrementAndGet();
            return Optional.of(stop);
        };
        // A fresh attempt, and a poll that keeps the QR: nothing to charge.
        Guard.Result first = Guard.run(tq, g("hook@acme.com", null).beforeStart(charge));
        Guard.Result keep = Guard.run(tq, g("hook@acme.com", token(first)).beforeStart(charge));
        assertEquals(List.of("enroll", 202, 0), List.of(step(first).get("state").asText(), keep.status(), calls.get()));
        // Linked: the push would start; the hook's answer is sent instead and nothing starts.
        api.link("hook@acme.com");
        int before = api.calls().size();
        assertEquals(stop, Guard.run(tq, g("hook@acme.com", token(first)).beforeStart(charge)));
        assertEquals(List.of(1, before + 1), List.of(calls.get(), api.calls().size()));   // the link state only
        Guard.Result waiting = Guard.run(tq, g("hook@acme.com", token(first)).beforeStart(() -> {
            calls.incrementAndGet();
            return Optional.empty();
        }));
        assertEquals(List.of("waiting", 2), List.of(step(waiting).get("state").asText(), calls.get()));
        // A QR in its last 15 s, and a QR Touchque no longer knows (404): called before the new QR.
        api.opts(Map.of("secretTtlMs", 10_000));
        Guard.Result near = Guard.run(tq, g("near@acme.com", null));
        assertEquals(stop, Guard.run(tq, g("near@acme.com", token(near)).beforeStart(charge)));
        api.reset();
        assertEquals(stop, Guard.run(tq, g("near@acme.com", token(near)).beforeStart(charge)));
        assertEquals(4, calls.get());
        assertEquals(List.of("GET"), api.calls().findValuesAsText("method"));   // no new secret
        // A waiting token is not a first-time QR: not called.
        api.link("near@acme.com");
        Guard.Result push = Guard.run(tq, g("near@acme.com", null));
        Guard.run(tq, g("near@acme.com", token(push)).beforeStart(charge));
        assertEquals(4, calls.get());
    }

    @Test
    void aPollThatWasAStatusPollStillGoesThroughBeforeStartWhenItRenewsTheQr() throws Exception {
        TouchqueClient tq = api.client();
        api.opts(Map.of("secretTtlMs", 16_000));   // 1 s above the 15 s margin
        Guard.Result first = Guard.run(tq, g("margin@acme.com", null));
        Guard.Input poll = g("margin@acme.com", token(first));
        assertTrue(Guard.isStatusPoll(tq, poll));   // a relay counts it on the poll budget...
        Thread.sleep(1_100);   // ...and the QR enters its last 15 s before the guard runs
        AtomicInteger calls = new AtomicInteger();
        Guard.Result renewed = Guard.run(tq, poll.beforeStart(() -> {
            calls.incrementAndGet();
            return Optional.empty();
        }));
        assertEquals(List.of(1, "data:image/png;base64,QR2-margin@acme.com"), List.of(calls.get(), step(renewed).get("enroll").get("qrCodeDataUrl").asText()));
    }

    @Test
    void guardFrozenRateLimitedBlocked() {
        api.link("blocked@acme.com");
        TouchqueClient tq = api.client();
        api.opts(Map.of("frozen", true));
        Guard.Result frozen = Guard.run(tq, g("blocked@acme.com", null));
        assertEquals(List.of(423, 900), List.of(frozen.status(), step(frozen).get("retryAfter").asInt()));
        assertEquals(900, frozen.retryAfter());
        api.opts(Map.of("frozen", false, "rateLimited", true));
        assertEquals(429, Guard.run(tq, g("blocked@acme.com", null)).status());
        api.opts(Map.of("rateLimited", false, "blocked", "geo_policy"));
        Guard.Result blocked = Guard.run(tq, g("blocked@acme.com", null));
        assertEquals(403, blocked.status());
        assertEquals(Json.parse("{\"state\":\"blocked\",\"reason\":\"geo_policy\",\"caseCode\":\"REF-USE\"}"), step(blocked));
    }

    @Test
    void qrPairingCreateScanThenAskThePhoneThatScanned() throws Exception {
        api.link("ayse@acme.com");
        TouchqueClient tq = api.client();
        QrPairings.Created p = tq.qrPairings().create(new QrPairings.CreateOptions(THUMB).clientIp("203.0.113.7").userAgent("Mozilla/5.0").browser("Chrome 155").os("macOS 15"));
        assertEquals(QrPairings.uri(p.pairingId(), p.nonce(), THUMB), p.uri());
        assertTrue(p.uri().matches("^touchque://pair-browser\\?v=1&p=[\\w-]{22}&n=[\\w-]{43}&k=[\\w-]{43}$"), p.uri());
        JsonNode list = api.get("/__test/qr-pairings");
        JsonNode stored = list.get(list.size() - 1);
        String hash = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(p.nonce().getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals(hash, stored.get("nonceHash").asText());
        assertEquals("waiting", tq.qrPairings().get(p.pairingId()).get("state").asText());
        TouchqueApiException early = assertThrows(TouchqueApiException.class, () -> tq.login().request(new LoginRequestOptions("ayse@acme.com").qrPairing(p.pairingId())));
        assertEquals("pairing_not_confirmed", early.code());

        api.post("/__test/qr-scan", Map.of("id", p.pairingId(), "user", "ayse@acme.com"));
        JsonNode seen = tq.qrPairings().get(p.pairingId());
        assertEquals(List.of("confirmed", "ayse@acme.com"), List.of(seen.get("state").asText(), seen.get("externalUsername").asText()));
        assertTrue(seen.get("proximity").get("warnings").isEmpty());
        Login.RequestResult req = tq.login().request(new LoginRequestOptions("ayse@acme.com").qrPairing(p.pairingId()));
        JsonNode after = tq.qrPairings().get(p.pairingId());
        assertEquals(List.of("requested", req.requestId()), List.of(after.get("state").asText(), after.get("requestId").asText()));
    }

    @Test
    void qrPairingRefuseAfterTheScanAndChecksBeforeTheCall() {
        api.link("ayse@acme.com");
        TouchqueClient tq = api.client();
        QrPairings.Created p = tq.qrPairings().create(new QrPairings.CreateOptions(THUMB).ttlSeconds(60));
        TouchqueApiException early = assertThrows(TouchqueApiException.class, () -> tq.qrPairings().refuse(p.pairingId(), "policy", "Not yet", null, null));
        assertEquals(List.of(409, "not_open"), List.of(early.status(), early.code()));
        api.post("/__test/qr-scan", Map.of("id", p.pairingId(), "user", "ayse@acme.com", "confirm", false));
        JsonNode refused = tq.qrPairings().refuse(p.pairingId(), "device_not_approved", "Ask IT to approve this computer.", null, "ABC-123");
        assertEquals(List.of("refused", "device_not_approved", "ABC-123"),
                List.of(refused.get("state").asText(), refused.get("outcome").get("reason").asText(), refused.get("outcome").get("deviceCode").asText()));
        assertThrows(TouchqueConfigException.class, () -> tq.qrPairings().create(new QrPairings.CreateOptions("short")));
        assertThrows(TouchqueConfigException.class, () -> tq.qrPairings().create(new QrPairings.CreateOptions(THUMB).ttlSeconds(10)));
        assertThrows(TouchqueConfigException.class, () -> tq.qrPairings().refuse(p.pairingId(), "nope", "x", null, null));
        assertThrows(TouchqueConfigException.class, () -> tq.qrPairings().refuse(p.pairingId(), "other", " ", null, null));
    }

    @Test
    void codeReplyOpensOnlyWithTheOneTimeKeyForThatRequest() {
        api.link("ayse@acme.com");
        TouchqueClient tq = api.client();
        com.touchque.crypto.CodeReply.Key key = com.touchque.crypto.CodeReply.newKey();
        Login.RequestResult sent = tq.login().request(new LoginRequestOptions("ayse@acme.com").reply(key.publicKey(), "sms", "+**********26"));
        assertNull(tq.login().status(sent.requestId()).reply());
        api.post("/__test/approve", Map.of("id", sent.requestId(), "replyCode", "482 913"));
        String ct = tq.login().status(sent.requestId()).reply().get("ct").asText();
        assertEquals("482 913", com.touchque.crypto.CodeReply.open(key.privateKey(), sent.requestId(), ct));
        assertNull(com.touchque.crypto.CodeReply.open(key.privateKey(), "another-request", ct));
        assertNull(com.touchque.crypto.CodeReply.open(com.touchque.crypto.CodeReply.newKey().privateKey(), sent.requestId(), ct));
        assertNull(com.touchque.crypto.CodeReply.open(key.privateKey(), sent.requestId(), "v1.bad.ct"));
    }
}
