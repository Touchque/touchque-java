package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.JsonNode;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.flow.Guard;
import com.touchque.flow.Steps;
import com.touchque.internal.Json;
import com.touchque.relay.RateLimit;
import com.touchque.relay.RelayHandler;
import com.touchque.relay.RelayOptions;
import com.touchque.relay.RelayRequest;
import com.touchque.relay.RelayResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The relay's POST /login: every start is charged like a fresh attempt, and guard refusals carry their state in headers. */
class RelayChargeTest {
    private final Support.FakeApi api = Support.FakeApi.get();

    @BeforeEach
    void reset() {
        api.reset();
    }

    private static RelayRequest<String> login(String user, String token) {
        return new RelayRequest<>("POST", "/login", Json.object(), "203.0.113.7", "UA", h -> h.equalsIgnoreCase(Guard.TOKEN_HEADER) ? token : null, user);
    }

    private int pushes() {
        int n = 0;
        for (JsonNode call : api.calls()) if ("/login/request".equals(call.get("path").asText())) n++;
        return n;
    }

    @Test
    void pollsThatKeepTheQrAreFreeAndEveryPushAReplayStartsIsCharged() {
        // 5 per user a minute (the default).
        RelayHandler<String> relay = new RelayHandler<>(api.client(), new RelayOptions<String>(r -> r).getLoginUser(r -> r));
        RelayResponse first = relay.handle(login("victim@acme.com", null));   // a fresh attempt: 1 of 5
        String token = first.body().get("token").asText();
        // Polls that only keep the QR are never charged.
        for (int i = 0; i < 8; i++) {
            RelayResponse keep = relay.handle(login("victim@acme.com", token));
            assertEquals(List.of(202, "enroll"), List.of(keep.status(), keep.body().get("touchque").get("state").asText()));
        }
        // Linked: each replay of the first token would start a push. Each is charged: 2 to 5 of 5, then 429.
        api.link("victim@acme.com");
        int before = pushes();
        List<Integer> statuses = new ArrayList<>();
        for (int i = 0; i < 6; i++) statuses.add(relay.handle(login("victim@acme.com", token)).status());
        assertEquals(List.of(202, 202, 202, 202, 429, 429), statuses);
        assertEquals(4, pushes() - before);
        RelayResponse over = relay.handle(login("victim@acme.com", token));
        assertEquals(List.of("RATE_LIMITED", "Too many attempts. Try again later."), List.of(over.body().get("error").asText(), over.body().get("message").asText()));
        assertEquals(List.of("rate_limited", "no-store"), List.of(over.header(Guard.STATE_HEADER), over.header("Cache-Control")));
        assertEquals(over.body().get("retryAfter").asText(), over.header("Retry-After"));
    }

    @Test
    void aRenewalIsChargedEvenWhenTheQrRanOutWhileTheLinkStateWasRead() throws Exception {
        // The poll arrives 300 ms before the QR's last 15 s; reading the link state takes 600 ms.
        try (Support.Stub stub = new Support.Stub(seen -> {
            if (seen.path().startsWith("/users/")) {
                try {
                    Thread.sleep(600);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return Support.Answer.json(200, Map.of("used", false));
            }
            if (seen.path().equals("/login/request")) return Support.Answer.json(404, Map.of("code", "device_not_linked", "error", "No linked device found for this user"));
            return Support.Answer.json(200, Map.of("qrCodeDataUrl", "data:image/png;base64,QR2", "expiresAt", Instant.now().plusSeconds(300).toString(), "recoveryCodes", List.of("r2")));
        })) {
            TouchqueClient tq = new TouchqueClient(new TouchqueOptions().apiKey("tq_k").apiSecret("s").baseUrl(stub.baseUrl));
            // 1 per user a minute.
            RelayHandler<String> relay = new RelayHandler<>(tq, new RelayOptions<String>(r -> r).getLoginUser(r -> r)
                    .rateLimit(new RateLimit.Options(Duration.ofMinutes(1), 100, 1, null)));
            List<Integer> statuses = new ArrayList<>();
            for (int i = 0; i < 2; i++) {
                long now = System.currentTimeMillis();
                ObjectNode claims = Json.object().put("u", "m@acme.com").put("a", "LOGIN").put("d", "").putNull("r").put("st", "enroll")
                        .put("ee", now + 15_300).put("exp", now + 60_000);
                statuses.add(relay.handle(login("m@acme.com", Steps.signGuardToken("s", claims))).status());
            }
            // The first renewal takes the user's one attempt; the second is refused instead of renewing on the poll budget.
            assertEquals(List.of(202, 429), statuses);
        }
    }

    @Test
    void guardRefusalsThroughTheRelayCarryTheirState() {
        api.link("frozen@acme.com");
        api.opts(Map.of("frozen", true));
        RelayHandler<String> relay = new RelayHandler<>(api.client(), new RelayOptions<String>(r -> r).getLoginUser(r -> r));
        RelayResponse frozen = relay.handle(login("frozen@acme.com", null));
        assertEquals(List.of(423, "frozen", "900"), List.of(frozen.status(), frozen.header(Guard.STATE_HEADER), frozen.header("Retry-After")));
        assertNull(frozen.header(Guard.REASON_HEADER));
        api.opts(Map.of("frozen", false, "blocked", "geo_policy"));
        RelayResponse blocked = relay.handle(login("frozen@acme.com", null));
        assertEquals(List.of(403, "blocked", "geo_policy"), List.of(blocked.status(), blocked.header(Guard.STATE_HEADER), blocked.header(Guard.REASON_HEADER)));
        api.opts(Map.of("blocked", false));
        RelayResponse waiting = relay.handle(login("frozen@acme.com", null));
        assertEquals(202, waiting.status());
        assertNull(waiting.header(Guard.STATE_HEADER));
    }
}
