package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.flow.Guard;
import com.touchque.flow.StartOptions;
import com.touchque.flow.Step;
import com.touchque.internal.Json;
import com.touchque.relay.RelayHandler;
import com.touchque.relay.RelayOptions;
import com.touchque.relay.RelayRequest;
import com.touchque.relay.RelayResponse;
import com.touchque.resources.Auth;
import com.touchque.resources.LoginRequestOptions;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * 2FA setup context: generate-secret and reset carry the browser's IP and User-Agent with the
 * login request's rules, every adapter that asks for a first-time QR sends the ones it sends for
 * the push, and validate's {@code setupContext} is read leniently ({@code fixtures/setup-context.json}).
 */
class SetupContextTest {
    private static final String IPHONE_SAFARI = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
            + "Version/18.1 Mobile/15E148 Safari/604.1";
    private static final String WINDOWS_FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0";
    private final Support.FakeApi api = Support.FakeApi.get();

    @BeforeEach
    void reset() {
        api.reset();
    }

    // ── request bodies ────────────────────────────────────────────────────

    /** Every request a stub answering {@code {"secret":"S"}} saw while {@code calls} ran: {path, body}. */
    private static List<List<Object>> sent(ThrowingConsumer<TouchqueClient> calls) throws Exception {
        List<Support.Seen> seen = new CopyOnWriteArrayList<>();
        try (Support.Stub stub = new Support.Stub(s -> {
            seen.add(s);
            return Support.Answer.json(200, Map.of("secret", "S"));
        })) {
            calls.accept(new TouchqueClient(new TouchqueOptions().apiKey("tq_k").apiSecret("s").baseUrl(stub.baseUrl)));
        }
        List<List<Object>> out = new ArrayList<>();
        for (Support.Seen s : seen) out.add(List.of(s.path(), Json.parse(s.body())));
        return out;
    }

    @FunctionalInterface
    private interface ThrowingConsumer<T> {
        void accept(T value) throws Exception;
    }

    private static JsonNode body(String json) {
        return Json.parse(json);
    }

    @Test
    void generateAndResetSendTheIpAndUserAgentOnlyWhenGiven() throws Exception {
        List<List<Object>> seen = sent(tq -> {
            tq.auth().generateSecret("ada@acme.com", "203.0.113.7", IPHONE_SAFARI);
            tq.auth().resetSecret("ada@acme.com", "203.0.113.7", IPHONE_SAFARI);
            tq.auth().generateSecret("ada@acme.com", "203.0.113.7", null);
            tq.auth().resetSecret("ada@acme.com", null, IPHONE_SAFARI);
            tq.auth().generateSecret("ada@acme.com", "", "");
            tq.auth().resetSecret("ada@acme.com", null, null);
            tq.auth().generateSecret("ada@acme.com");
            tq.auth().resetSecret("ada@acme.com");
        });
        String both = "{\"externalUsername\":\"ada@acme.com\",\"clientIp\":\"203.0.113.7\",\"userAgent\":" + Json.jsString(IPHONE_SAFARI) + "}";
        String none = "{\"externalUsername\":\"ada@acme.com\"}";
        assertEquals(List.of(
                List.of("/auth/generate-secret", body(both)),
                List.of("/auth/secret/reset", body(both)),
                List.of("/auth/generate-secret", body("{\"externalUsername\":\"ada@acme.com\",\"clientIp\":\"203.0.113.7\"}")),
                List.of("/auth/secret/reset", body("{\"externalUsername\":\"ada@acme.com\",\"userAgent\":" + Json.jsString(IPHONE_SAFARI) + "}")),
                List.of("/auth/generate-secret", body(none)),
                List.of("/auth/secret/reset", body(none)),
                // The one-argument forms send what they sent before.
                List.of("/auth/generate-secret", body(none)),
                List.of("/auth/secret/reset", body(none))), seen);
    }

    @Test
    void theIpAndUserAgentFollowTheLoginRequestsRules() throws Exception {
        // Whatever a login request sends for clientIp and userAgent, generate and reset send the same:
        // null and "" left out, nothing trimmed, no length cap, no address check.
        String longUserAgent = "Mozilla/5.0 " + "x".repeat(3000);
        List<String[]> inputs = List.of(new String[] {null, null}, new String[] {"", ""}, new String[] {" 203.0.113.7 ", " UA "},
                new String[] {"::ffff:203.0.113.7", longUserAgent}, new String[] {"not an address", "line\nbreak\t"}, new String[] {" ", " "});
        List<List<Object>> seen = sent(tq -> {
            for (String[] in : inputs) {
                tq.auth().generateSecret("ada@acme.com", in[0], in[1]);
                tq.auth().resetSecret("ada@acme.com", in[0], in[1]);
            }
        });
        assertEquals(inputs.size() * 2, seen.size());
        for (int i = 0; i < seen.size(); i++) {
            String[] in = inputs.get(i / 2);
            ObjectNode login = new LoginRequestOptions("ada@acme.com").clientIp(in[0]).userAgent(in[1]).toJson();
            JsonNode secret = (JsonNode) seen.get(i).get(1);
            assertEquals(Arrays.asList(login.get("clientIp"), login.get("userAgent")), Arrays.asList(secret.get("clientIp"), secret.get("userAgent")),
                    "input " + Arrays.toString(in));
        }
        // The long User-Agent went in full.
        assertEquals(longUserAgent, ((JsonNode) seen.get(6).get(1)).get("userAgent").asText());
    }

    // ── adapters: the first-time QR gets the IP and User-Agent of the push ──

    /** The bodies of the fake's calls to {@code path}, in order. */
    private List<JsonNode> bodies(String path) {
        List<JsonNode> out = new ArrayList<>();
        for (JsonNode call : api.calls()) {
            if (path.equals(call.get("path").asText())) out.add(call.get("body"));
        }
        return out;
    }

    /** {clientIp, userAgent} of a request body (null when not sent). */
    private static List<String> ipAndUa(JsonNode body) {
        return Arrays.asList(Json.str(body, "clientIp"), Json.str(body, "userAgent"));
    }

    private static List<String> ipAndUa(String ip, String ua) {
        return Arrays.asList(ip, ua);
    }

    private static String token(Guard.Result r) {
        return r.body().get("token").asText();
    }

    @Test
    void theGuardAsksForTheFirstTimeQrAndItsRenewalWithThePushsIpAndUserAgent() {
        TouchqueClient tq = api.client();
        api.opts(Map.of("secretTtlMs", 10_000));   // within 15 s of its expiry: the next poll renews the QR
        Guard.Input input = new Guard.Input("qr-ctx@acme.com", "LOGIN").ip("203.0.113.7").userAgent(IPHONE_SAFARI);
        Guard.Result first = Guard.run(tq, input);
        assertEquals("enroll", first.step().state());
        Guard.Result renewed = Guard.run(tq, new Guard.Input("qr-ctx@acme.com", "LOGIN").ip("203.0.113.7").userAgent(IPHONE_SAFARI).token(token(first)));
        assertEquals("data:image/png;base64,QR2-qr-ctx@acme.com", renewed.step().enroll().qrCodeDataUrl());

        List<String> expected = ipAndUa("203.0.113.7", IPHONE_SAFARI);
        List<JsonNode> logins = bodies("/login/request");
        List<JsonNode> generated = bodies("/auth/generate-secret");
        List<JsonNode> resets = bodies("/auth/secret/reset");
        assertEquals(List.of(2, 2, 1), List.of(logins.size(), generated.size(), resets.size()));
        for (JsonNode b : logins) assertEquals(expected, ipAndUa(b));
        for (JsonNode b : generated) assertEquals(expected, ipAndUa(b));
        assertEquals(expected, ipAndUa(resets.get(0)));

        // The phone sees where it was asked for.
        Auth.SetupContext where = Auth.SetupContext.of(tq.auth().validateSecret("S2"));
        assertEquals(List.of("203.0.113.7", new Auth.SetupLocation("Berlin", "Germany", "DE"), new Auth.SetupDevice("Safari", "iOS", "iPhone")),
                Arrays.asList(where.ip(), where.location(), where.device()));
    }

    @Test
    void aGuardWithoutAnIpOrUserAgentSendsNeitherForTheQrAsForThePush() {
        TouchqueClient tq = api.client();
        assertEquals("enroll", Guard.run(tq, new Guard.Input("bare@acme.com", "LOGIN").ip("").userAgent(null)).step().state());
        List<JsonNode> sentBodies = new ArrayList<>(bodies("/login/request"));
        sentBodies.addAll(bodies("/auth/generate-secret"));
        assertEquals(2, sentBodies.size());
        for (JsonNode b : sentBodies) assertEquals(List.of(false, false), List.of(b.has("clientIp"), b.has("userAgent")), b.toString());
        assertNull(Auth.SetupContext.of(tq.auth().validateSecret("S")));
    }

    @Test
    void startAsksForTheFirstTimeQrWithItsIpAndUserAgent() {
        TouchqueClient tq = api.client();
        Step step = tq.start("LOGIN", new StartOptions("start-ctx@acme.com").ip("198.51.100.23").userAgent(WINDOWS_FIREFOX));
        assertEquals("enroll", step.state());
        // A second start: generate answers 409 (a QR is up, not scanned), so the QR is reset with the same IP and User-Agent.
        assertEquals("data:image/png;base64,QR2-start-ctx@acme.com",
                tq.start("LOGIN", new StartOptions("start-ctx@acme.com").ip("198.51.100.23").userAgent(WINDOWS_FIREFOX)).enroll().qrCodeDataUrl());
        List<String> expected = ipAndUa("198.51.100.23", WINDOWS_FIREFOX);
        for (String path : List.of("/login/request", "/auth/generate-secret", "/auth/secret/reset")) {
            List<JsonNode> b = bodies(path);
            assertFalse(b.isEmpty(), path);
            for (JsonNode one : b) assertEquals(expected, ipAndUa(one), path);
        }
    }

    @Test
    void theRelaySendsTheRequestsIpAndUserAgentForTheQrAsForItsLogin() {
        TouchqueClient tq = api.client();
        RelayHandler<String> relay = new RelayHandler<>(tq, new RelayOptions<String>(req -> req).getLoginUser(req -> req));

        // POST /login for a user with no phone: the push request, then the first-time QR, both with the request's IP and User-Agent.
        RelayResponse login = relay.handle(new RelayRequest<>("POST", "/login", Json.object(), "203.0.113.7", IPHONE_SAFARI, h -> null, "relay-login@acme.com"));
        assertEquals(List.of(202, "enroll"), List.of(login.status(), login.body().get("touchque").get("state").asText()));
        List<String> fromLogin = ipAndUa("203.0.113.7", IPHONE_SAFARI);
        assertEquals(fromLogin, ipAndUa(bodies("/login/request").get(0)));
        assertEquals(fromLogin, ipAndUa(bodies("/auth/generate-secret").get(0)));

        // POST /enroll/start: generate; again while that QR is up (409): reset. Same IP and User-Agent.
        RelayRequest<String> start = new RelayRequest<>("POST", "/enroll/start", Json.object(), "198.51.100.23", WINDOWS_FIREFOX, h -> null, "relay-enroll@acme.com");
        assertEquals(200, relay.handle(start).status());
        RelayResponse again = relay.handle(start);
        assertEquals(List.of(200, "data:image/png;base64,QR2-relay-enroll@acme.com"), List.of(again.status(), again.body().get("qrCodeDataUrl").asText()));
        List<String> fromStart = ipAndUa("198.51.100.23", WINDOWS_FIREFOX);
        assertEquals(fromStart, ipAndUa(bodies("/auth/generate-secret").get(1)));
        assertEquals(fromStart, ipAndUa(bodies("/auth/generate-secret").get(2)));
        assertEquals(fromStart, ipAndUa(bodies("/auth/secret/reset").get(0)));
        Auth.SetupContext where = Auth.SetupContext.of(tq.auth().validateSecret("S2"));
        assertEquals(List.of("198.51.100.23", new Auth.SetupLocation("New York", "United States", "US"), new Auth.SetupDevice("Firefox", "Windows", null)),
                Arrays.asList(where.ip(), where.location(), where.device()));

        // An unknown IP ("", as an adapter passes it) and no User-Agent: neither is sent, on /login as on /enroll/start.
        relay.handle(new RelayRequest<>("POST", "/login", Json.object(), "", null, h -> null, "relay-none@acme.com"));
        relay.handle(new RelayRequest<>("POST", "/enroll/start", Json.object(), "", null, h -> null, "relay-none2@acme.com"));
        List<JsonNode> logins = bodies("/login/request");
        List<JsonNode> generated = bodies("/auth/generate-secret");
        assertEquals(List.of(2, 5), List.of(logins.size(), generated.size()));
        for (JsonNode b : List.of(logins.get(1), generated.get(3), generated.get(4))) {
            assertEquals(List.of(false, false), List.of(b.has("clientIp"), b.has("userAgent")), b.toString());
        }
    }

    @Test
    void theRelayStillRefusesToReplaceALinkedPhone() {
        api.link("linked@acme.com");
        RelayHandler<String> relay = new RelayHandler<>(api.client(), new RelayOptions<String>(req -> req));
        RelayResponse res = relay.handle(new RelayRequest<>("POST", "/enroll/start", Json.object(), "203.0.113.7", IPHONE_SAFARI, h -> null, "linked@acme.com"));
        assertEquals(List.of(409, "already_linked"), List.of(res.status(), res.body().get("error").asText()));
        assertTrue(bodies("/auth/secret/reset").isEmpty());
    }

    // ── setupContext on validate ──────────────────────────────────────────

    @Test
    void setupContextIsReadLenientlyAsTheSharedFixtureExpects() {
        ObjectNode fixture = Support.fixture("setup-context.json");
        JsonNode expected = fixture.get("expected");
        List<String> cases = new ArrayList<>();
        for (Iterator<String> it = fixture.fieldNames(); it.hasNext();) {
            String name = it.next();
            if (!name.equals("expected")) cases.add(name);
        }
        assertEquals(Set.of("full", "allNull", "missing", "null", "wrongTypes", "extraFields"), new HashSet<>(cases));
        for (String name : cases) {
            Auth.SetupContext parsed = Auth.SetupContext.of(fixture.get(name));
            JsonNode want = expected.get(name);
            if (want.isNull()) assertNull(parsed, name);
            else assertEquals(want, Json.toNode(parsed), name);
            // parse reads the raw value (Java null for "missing", a JSON null for "null") the same way.
            assertEquals(parsed, Auth.SetupContext.parse(fixture.get(name).get("setupContext")), name);
        }
        Auth.SetupContext full = Auth.SetupContext.of(fixture.get("full"));
        assertEquals(new Auth.SetupContext("203.0.113.7", new Auth.SetupLocation("Berlin", "Germany", "DE"), new Auth.SetupDevice("Safari", "iOS", "iPhone"),
                "2026-11-16T09:30:00.000Z", true), full);
        // A device object whose fields all have the wrong type stays an object of nulls; a location that is not an object is null.
        Auth.SetupContext wrong = Auth.SetupContext.of(fixture.get("wrongTypes"));
        assertEquals(Arrays.asList(null, null, new Auth.SetupDevice(null, null, null), null), Arrays.asList(wrong.ip(), wrong.location(), wrong.device(), wrong.farFromPhone()));
        assertEquals(Boolean.FALSE, Auth.SetupContext.of(fixture.get("extraFields")).farFromPhone());
    }

    @Test
    void anythingElseIsNullNeverAnException() {
        // No answer, or one that is not an object.
        for (String answer : Arrays.asList(null, "null", "[]", "\"setupContext\"", "42", "{}")) {
            assertNull(Auth.SetupContext.of(answer == null ? null : Json.parse(answer)), String.valueOf(answer));
        }
        // setupContext of the wrong type.
        for (String value : List.of("\"Berlin\"", "[]", "[{\"ip\":\"203.0.113.7\"}]", "7", "true", "false")) {
            assertNull(Auth.SetupContext.of(Json.parse("{\"valid\":true,\"setupContext\":" + value + "}")), value);
        }
        // Each field of the wrong type, or missing.
        Auth.SetupContext empty = Auth.SetupContext.of(Json.parse("{\"setupContext\":{}}"));
        assertEquals(new Auth.SetupContext(null, null, null, null, null), empty);
        Auth.SetupContext odd = Auth.SetupContext.of(Json.parse("{\"setupContext\":{\"ip\":[\"203.0.113.7\"],\"location\":[\"Berlin\"],"
                + "\"device\":\"Safari on iOS\",\"requestedAt\":1763285400000,\"farFromPhone\":1}}"));
        assertEquals(new Auth.SetupContext(null, null, null, null, null), odd);
        Auth.SetupContext partial = Auth.SetupContext.of(Json.parse("{\"setupContext\":{\"ip\":\"203.0.113.7\",\"location\":{\"city\":7,\"country\":{\"name\":\"Germany\"},"
                + "\"countryCode\":\"DE\"},\"device\":{\"os\":\"iOS\"},\"requestedAt\":null,\"farFromPhone\":false}}"));
        assertEquals(new Auth.SetupContext("203.0.113.7", new Auth.SetupLocation(null, null, "DE"), new Auth.SetupDevice(null, "iOS", null), null, false), partial);

        // parse takes the raw value: null (Java or JSON), missing, or anything but an object is null.
        for (JsonNode raw : Arrays.asList(null, NullNode.getInstance(), MissingNode.getInstance(), Json.object().path("setupContext"))) {
            assertNull(Auth.SetupContext.parse(raw), String.valueOf(raw));
        }
        for (String value : List.of("\"Berlin\"", "\"\"", "[]", "[{\"ip\":\"203.0.113.7\"}]", "0", "7", "1.5", "true", "false")) {
            assertNull(Auth.SetupContext.parse(Json.parse(value)), value);
        }
    }

    @Test
    void ofIsParseOfTheAnswersSetupContext() {
        String full = "{\"ip\":\"203.0.113.7\",\"location\":{\"city\":\"Berlin\",\"country\":\"Germany\",\"countryCode\":\"DE\"},"
                + "\"device\":{\"browser\":\"Safari\",\"os\":\"iOS\",\"model\":\"iPhone\"},\"requestedAt\":\"2026-11-16T09:30:00.000Z\",\"farFromPhone\":true}";
        String emptyStrings = "{\"ip\":\"\",\"location\":{\"city\":\"\",\"region\":\"BE\"},\"device\":{},\"requestedAt\":\"\",\"farFromPhone\":false,\"asn\":7922}";
        String wrongTypes = "{\"ip\":[\"203.0.113.7\"],\"location\":[\"Berlin\"],\"device\":\"Safari on iOS\",\"requestedAt\":1763285400000,\"farFromPhone\":1}";
        for (String raw : List.of("null", "\"Berlin\"", "[]", "7", "true", "{}", full, emptyStrings, wrongTypes)) {
            assertEquals(Auth.SetupContext.parse(Json.parse(raw)), Auth.SetupContext.of(Json.parse("{\"valid\":true,\"setupContext\":" + raw + "}")), raw);
        }
        assertEquals(new Auth.SetupContext("203.0.113.7", new Auth.SetupLocation("Berlin", "Germany", "DE"), new Auth.SetupDevice("Safari", "iOS", "iPhone"),
                "2026-11-16T09:30:00.000Z", true), Auth.SetupContext.parse(Json.parse(full)));
        // Empty strings are strings, kept as sent; an empty device object is an object of nulls; unknown fields are dropped.
        assertEquals(new Auth.SetupContext("", new Auth.SetupLocation("", null, null), new Auth.SetupDevice(null, null, null), "", false),
                Auth.SetupContext.parse(Json.parse(emptyStrings)));
    }

    // ── end to end against the shared fake ────────────────────────────────

    @Test
    void validateShowsWhereTheQrWasAskedFor() {
        TouchqueClient tq = api.client();
        Instant before = Instant.now().minus(Duration.ofSeconds(5));
        tq.auth().generateSecret("e2e@acme.com", "203.0.113.7", IPHONE_SAFARI);
        JsonNode answer = tq.auth().validateSecret("S");
        assertTrue(answer.get("valid").asBoolean());
        Auth.SetupContext where = Auth.SetupContext.of(answer);
        assertNotNull(where);
        assertEquals(List.of("203.0.113.7", new Auth.SetupLocation("Berlin", "Germany", "DE"), new Auth.SetupDevice("Safari", "iOS", "iPhone")),
                Arrays.asList(where.ip(), where.location(), where.device()));
        assertNull(where.farFromPhone());
        Instant at = Instant.parse(where.requestedAt());
        assertTrue(!at.isBefore(before) && !at.isAfter(Instant.now().plus(Duration.ofSeconds(5))), where.requestedAt());

        // A reset from another browser replaces it: the new QR shows that browser, the old one is gone.
        tq.auth().resetSecret("e2e@acme.com", "198.51.100.23", WINDOWS_FIREFOX);
        Auth.SetupContext reset = Auth.SetupContext.of(tq.auth().validateSecret("S2"));
        assertEquals(List.of("198.51.100.23", new Auth.SetupLocation("New York", "United States", "US"), new Auth.SetupDevice("Firefox", "Windows", null)),
                Arrays.asList(reset.ip(), reset.location(), reset.device()));
        TouchqueApiException gone = assertThrows(TouchqueApiException.class, () -> tq.auth().validateSecret("S"));
        assertEquals(List.of(404, "not_found"), List.of(gone.status(), gone.reason()));

        // An address the fake's GeoIP does not know: no location, the device still shows.
        tq.auth().generateSecret("elsewhere@acme.com", "192.0.2.1", WINDOWS_FIREFOX);
        Auth.SetupContext unknown = Auth.SetupContext.of(tq.auth().validateSecret("S"));
        assertEquals(Arrays.asList("192.0.2.1", null, new Auth.SetupDevice("Firefox", "Windows", null)), Arrays.asList(unknown.ip(), unknown.location(), unknown.device()));

        // A QR asked for without an IP or User-Agent, and a server answering setupContext: null.
        tq.auth().generateSecret("plain@acme.com");
        assertNull(Auth.SetupContext.of(tq.auth().validateSecret("S")));
        api.opts(Map.of("setupContextNull", true));
        assertNull(Auth.SetupContext.of(tq.auth().validateSecret("S2")));
    }

    @Test
    void aResetRecordsTheContextAndOneGivenNeitherDropsIt() {
        TouchqueClient tq = api.client();
        tq.auth().generateSecret("renew@acme.com", "203.0.113.7", IPHONE_SAFARI);
        assertEquals("203.0.113.7", Auth.SetupContext.of(tq.auth().validateSecret("S")).ip());
        // The one-argument reset, and one given null or "", send neither: the new QR has no setup context.
        tq.auth().resetSecret("renew@acme.com");
        assertNull(Auth.SetupContext.of(tq.auth().validateSecret("S2")));
        tq.auth().resetSecret("renew@acme.com", "", null);
        assertNull(Auth.SetupContext.of(tq.auth().validateSecret("S2")));
        // A reset that names the browser records it again.
        tq.auth().resetSecret("renew@acme.com", "198.51.100.23", WINDOWS_FIREFOX);
        Auth.SetupContext renewed = Auth.SetupContext.of(tq.auth().validateSecret("S2"));
        assertEquals(List.of("198.51.100.23", new Auth.SetupDevice("Firefox", "Windows", null)), Arrays.asList(renewed.ip(), renewed.device()));
    }
}
