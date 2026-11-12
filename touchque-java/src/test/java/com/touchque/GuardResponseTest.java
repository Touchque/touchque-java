package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.touchque.flow.Approval;
import com.touchque.flow.Guard;
import com.touchque.flow.Step;
import com.touchque.flow.Steps;
import com.touchque.internal.Json;
import com.touchque.relay.RelayHandler;
import com.touchque.relay.RelayOptions;
import com.touchque.relay.RelayRequest;
import com.touchque.relay.RelayResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** Guard.response: a guard result that is not an approval as its HTTP answer, the same one the relay and @RequireTouchque send. */
class GuardResponseTest {
    private static Guard.Result result(int status, Step step) {
        ObjectNode body = Json.object();
        body.set("touchque", Steps.toJson(step));
        body.put("token", "v1.x.y");
        return new Guard.Result(status, null, body, step);
    }

    private static final Guard.Result WAITING = result(202, Step.of("waiting").withRequestId("r1").withNumber("47"));
    private static final Guard.Result BLOCKED = result(403, Step.of("blocked").withReason("geo_policy"));
    private static final Guard.Result LIMITED = result(429, Step.of("rate_limited").withRetryAfter(60));
    private static final Guard.Result FROZEN = result(423, Step.of("frozen").withRetryAfter(900));
    private static final Guard.Result MISCONFIGURED = Guard.withoutClient(new Guard.Input("jane@acme.com", "LOGIN"));

    public record Shape(String errorCode, String errorMessage) {
    }

    /** Throws a checked exception from a lambda, as Kotlin or @SneakyThrows code can. */
    @SuppressWarnings("unchecked")
    static <E extends Exception> Object sneakyThrow(Exception e) throws E {
        throw (E) e;
    }

    @Test
    void withoutAnErrorBodyTheAnswerIsTheGuardsBodyWithItsHeaders() {
        assertEquals(new Guard.Response(202, Map.of("Cache-Control", "no-store"), WAITING.body()), Guard.response(WAITING, null));
        assertEquals(new Guard.Response(403, Map.of("Cache-Control", "no-store", "X-Touchque-State", "blocked", "X-Touchque-Reason", "geo_policy"), BLOCKED.body()),
                Guard.response(BLOCKED, null));
        assertEquals(new Guard.Response(429, Map.of("Cache-Control", "no-store", "Retry-After", "60", "X-Touchque-State", "rate_limited"), LIMITED.body()),
                Guard.response(LIMITED, null));
        assertEquals(new Guard.Response(423, Map.of("Cache-Control", "no-store", "Retry-After", "900", "X-Touchque-State", "frozen"), FROZEN.body()),
                Guard.response(FROZEN, null));
        assertEquals(new Guard.Response(500, Map.of("Cache-Control", "no-store", "X-Touchque-State", "blocked", "X-Touchque-Reason", "misconfigured"),
                MISCONFIGURED.body()), Guard.response(MISCONFIGURED, null));
        Approval approval = new Approval("r1", "a", "LOGIN", null, "DEVICE", null, null, null, null, null, null);
        assertThrows(IllegalArgumentException.class, () -> Guard.response(new Guard.Result(200, approval, null, null), null));
    }

    @Test
    void anErrorBodyShapesRefusalsOnlyAndTheStepWins() {
        List<Guard.Refusal> seen = new ArrayList<>();
        Guard.ErrorBody shape = r -> {
            seen.add(r);
            return Map.of("message", r.message(), "code", r.code(), "touchque", "not the step");
        };
        // Never for a 202 step.
        assertEquals(new Guard.Response(202, Map.of("Cache-Control", "no-store"), WAITING.body()), Guard.response(WAITING, shape));
        assertEquals(List.of(), seen);
        // An object gets the step under "touchque" (no token); the status and headers stay.
        Guard.Response limited = Guard.response(LIMITED, shape);
        assertEquals(new Guard.Response(429, Map.of("Cache-Control", "no-store", "Retry-After", "60", "X-Touchque-State", "rate_limited"),
                Json.parse("{\"message\":\"Too many attempts. Try again later.\",\"code\":\"rate_limited\",\"touchque\":{\"state\":\"rate_limited\",\"retryAfter\":60}}")),
                limited);
        assertEquals(Json.parse("{\"message\":\"Two-factor approval is not configured correctly.\",\"code\":\"misconfigured\","
                + "\"touchque\":{\"state\":\"blocked\",\"reason\":\"misconfigured\"}}"), Guard.response(MISCONFIGURED, shape).body());
        // Anything that is not an object is sent as it is: the state is in the headers.
        Guard.Response text = Guard.response(BLOCKED, r -> "refused: " + r.code());
        assertEquals(List.of(TextNode.valueOf("refused: geo_policy"), "blocked", "geo_policy"),
                List.of(text.body(), text.headers().get(Guard.STATE_HEADER), text.headers().get(Guard.REASON_HEADER)));
        assertEquals(NullNode.instance, Guard.response(BLOCKED, r -> null).body());
        assertEquals(Json.parse("[1,2]"), Guard.response(BLOCKED, r -> List.of(1, 2)).body());
        // The callback gets a copy of the step.
        Guard.Response mutated = Guard.response(FROZEN, r -> {
            ((ObjectNode) r.touchque()).put("state", "approved");
            return Map.of();
        });
        assertEquals(List.of("frozen", "frozen"), List.of(mutated.body().get("touchque").get("state").asText(), FROZEN.body().get("touchque").get("state").asText()));
        // A result that carries only its step (a beforeStart hook's 429): the object still gets it.
        Guard.Result hook = new Guard.Result(429, null, Json.object().put("error", "RATE_LIMITED"), Step.of("rate_limited").withRetryAfter(7));
        assertEquals(Json.parse("{\"code\":\"rate_limited\",\"touchque\":{\"state\":\"rate_limited\",\"retryAfter\":7}}"),
                Guard.response(hook, r -> Map.of("code", r.code())).body());
    }

    @Test
    void theAppsObjectMapperWritesTheResult() {
        ObjectMapper snake = new ObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        Guard.ErrorBody shape = r -> new Shape(r.code(), r.message());
        assertEquals(Json.parse("{\"error_code\":\"geo_policy\",\"error_message\":\"The approval was refused.\",\"touchque\":{\"state\":\"blocked\",\"reason\":\"geo_policy\"}}"),
                Guard.response(BLOCKED, shape, snake, null).body());
        assertEquals(Json.parse("{\"errorCode\":\"geo_policy\",\"errorMessage\":\"The approval was refused.\",\"touchque\":{\"state\":\"blocked\",\"reason\":\"geo_policy\"}}"),
                Guard.response(BLOCKED, shape).body());
    }

    @Test
    void aFailingErrorBodySendsTheDefaultBodyAndLogsWhyToTheLoggerGiven() {
        LoggingTest.ListLogger logger = new LoggingTest.ListLogger();
        Map<String, Object> cycle = new HashMap<>();
        cycle.put("self", cycle);
        Map<String, Object> deep = new HashMap<>();
        Map<String, Object> level = deep;
        for (int i = 0; i < 1500; i++) {
            Map<String, Object> next = new HashMap<>();
            level.put("n", next);
            level = next;
        }
        List<Guard.ErrorBody> failing = List.of(
                r -> {
                    throw new IllegalStateException("the error template is broken");
                },
                r -> sneakyThrow(new IOException("a checked one")),
                r -> cycle,
                r -> deep);
        for (Guard.ErrorBody errorBody : failing) {
            Guard.Response res = Guard.response(FROZEN, errorBody, null, logger);
            assertEquals(new Guard.Response(423, Map.of("Cache-Control", "no-store", "Retry-After", "900", "X-Touchque-State", "frozen"), FROZEN.body()), res);
        }
        assertEquals(4, logger.lines.size());
        assertEquals(List.of("ERROR [Touchque] errorBody failed: the error template is broken", "ERROR [Touchque] errorBody failed: a checked one"),
                logger.lines.subList(0, 2));
        for (String line : logger.lines) assertTrue(line.startsWith("ERROR [Touchque] errorBody failed: "), line);
        // Without a logger, the same answer and nothing logged anywhere.
        assertEquals(FROZEN.body(), Guard.response(FROZEN, r -> {
            throw new IllegalStateException("quiet");
        }).body());
    }

    /** The relay's POST /login answers exactly what Guard.response builds for the same guard result (it uses it). */
    @Test
    void theRelaySendsWhatTheHelperBuilds() throws Exception {
        AtomicReference<Support.Answer> answer = new AtomicReference<>();
        try (Support.Stub stub = new Support.Stub(seen -> answer.get())) {
            TouchqueClient tq = new TouchqueClient(new TouchqueOptions().apiKey("tq_k").apiSecret("s").baseUrl(stub.baseUrl));
            RelayHandler<String> relay = new RelayHandler<>(tq, new RelayOptions<String>(r -> r).getLoginUser(r -> r).rateLimit(null));
            Map<String, Support.Answer> scenarios = new LinkedHashMap<>();
            scenarios.put("202", Support.Answer.json(200, Map.of("requestId", "r1", "challengeCode", "47", "expiresAt", "2030-01-01T00:00:00.000Z", "caseCode", "K7P-2QX")));
            scenarios.put("403", Support.Answer.json(403, Map.of("code", "blocked", "reason", "geo_policy", "error", "blocked", "caseCode", "REF-USE")));
            scenarios.put("429", new Support.Answer(429, Map.of("code", "rate_limited", "error", "too_many_login_requests"), Map.of("Retry-After", "60")));
            scenarios.put("423", Support.Answer.json(423, Map.of("code", "frozen", "error", "frozen", "retryAfter", 900)));
            scenarios.put("500", Support.Answer.json(400, Map.of("code", "unknown_action", "error", "Invalid action type: LOGIN")));
            for (Map.Entry<String, Support.Answer> scenario : scenarios.entrySet()) {
                answer.set(scenario.getValue());
                RelayRequest<String> req = new RelayRequest<>("POST", "/login", Json.object(), "203.0.113.7", "UA", h -> null, "jane@acme.com");
                RelayResponse sent = relay.handle(req);
                Guard.Response built = Guard.response(Guard.run(tq, RelayHandler.guardInput(req, "jane@acme.com", "LOGIN", null, true, null)), null);
                Map<String, String> headers = new LinkedHashMap<>();
                sent.headers().forEach(h -> headers.put(h.getKey(), h.getValue()));
                assertEquals(List.of(Integer.parseInt(scenario.getKey()), built.headers(), withoutToken(built.body())),
                        List.of(sent.status(), headers, withoutToken(sent.body())), scenario.getKey());
                assertEquals(built.status(), sent.status());
            }
        }
    }

    /** A token signs a timestamp: two runs differ only there. */
    private static JsonNode withoutToken(JsonNode body) {
        JsonNode copy = body.deepCopy();
        if (copy instanceof ObjectNode o) o.remove("token");
        return copy;
    }
}
