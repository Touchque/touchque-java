package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.flow.Approval;
import com.touchque.flow.Guard;
import com.touchque.flow.Step;
import com.touchque.flow.Steps;
import com.touchque.internal.Json;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** What an adapter's errorBody sees of a refusal, and the answer without a client. No API needed. */
class GuardRefusalTest {
    private static Guard.Result refused(int status, Step step) {
        ObjectNode body = Json.object();
        body.set("touchque", Steps.toJson(step));
        body.put("token", "v1.x.y");
        return new Guard.Result(status, null, body, step);
    }

    private static List<Object> of(Guard.Result r) {
        Guard.Refusal refusal = Guard.Refusal.of(r);
        return List.of(refusal.status(), refusal.code(), refusal.message());
    }

    @Test
    void codeAndMessageComeFromTheErrorElseTheReasonElseTheState() {
        assertEquals(List.of(403, "rejected", "The approval was rejected."), of(refused(403, Step.of("rejected").withRequestId("r1"))));
        assertEquals(List.of(403, "request_rejected", "The approval was rejected."), of(refused(403, Step.of("rejected").withReason("request_rejected"))));
        assertEquals(List.of(408, "already_used", "The approval expired. Try again."), of(refused(408, Step.of("expired").withReason("already_used"))));
        assertEquals(List.of(423, "frozen", "Too many rejected approvals. Try again later."), of(refused(423, Step.of("frozen").withRetryAfter(900))));
        assertEquals(List.of(429, "rate_limited", "Too many attempts. Try again later."), of(refused(429, Step.of("rate_limited").withRetryAfter(60))));
        assertEquals(List.of(403, "geo_policy", "The approval was refused."), of(refused(403, Step.of("blocked").withReason("geo_policy"))));
        Guard.Result unauthenticated = Guard.withoutClient(new Guard.Input(null, "LOGIN"));
        assertEquals(List.of(401, "unauthenticated", "Sign in first."), of(unauthenticated));
        assertEquals(Json.parse("{\"state\":\"blocked\",\"reason\":\"unauthenticated\"}"), Guard.Refusal.of(unauthenticated).touchque());
    }

    @Test
    void refusalsCarryTheirStateAndReasonInHeaders() {
        assertEquals(Map.of(Guard.STATE_HEADER, "frozen"), refused(423, Step.of("frozen").withRetryAfter(900)).refusalHeaders());
        assertEquals(Map.of(Guard.STATE_HEADER, "blocked", Guard.REASON_HEADER, "geo_policy"), refused(403, Step.of("blocked").withReason("geo_policy")).refusalHeaders());
        assertEquals(Map.of(Guard.STATE_HEADER, "blocked", Guard.REASON_HEADER, "misconfigured"),
                Guard.withoutClient(new Guard.Input("jane@acme.com", "LOGIN")).refusalHeaders());
        assertEquals(Map.of(), refused(202, Step.of("waiting").withRequestId("r1")).refusalHeaders());
        assertEquals(List.of("X-Touchque-State", "X-Touchque-Reason"), List.of(Guard.STATE_HEADER, Guard.REASON_HEADER));
    }

    @Test
    void stepsAndApprovalsAreNotRefusals() {
        assertNull(Guard.Refusal.of(refused(202, Step.of("waiting").withRequestId("r1"))));
        assertNull(Guard.Refusal.of(new Guard.Result(200, new Approval("r1", "a", "LOGIN", null, "DEVICE", null, null, null, null, null, null), null, null)));
    }

    @Test
    void withoutAClientTheGuardAnswers401Or500Misconfigured() {
        Guard.Result anonymous = Guard.withoutClient(new Guard.Input(null, "SEND_MONEY"));
        assertEquals(401, anonymous.status());
        assertEquals(Json.parse("{\"touchque\":{\"state\":\"blocked\",\"reason\":\"unauthenticated\"},\"error\":{\"code\":\"unauthenticated\",\"message\":\"Sign in first.\"}}"),
                anonymous.body());
        Guard.Result signedIn = Guard.withoutClient(new Guard.Input("jane@acme.com", "SEND_MONEY"));
        assertEquals(500, signedIn.status());
        assertEquals(Json.parse("{\"touchque\":{\"state\":\"blocked\",\"reason\":\"misconfigured\"},\"error\":{\"code\":\"misconfigured\","
                + "\"message\":\"Two-factor approval is not configured correctly.\"}}"), signedIn.body());
        assertEquals(List.of(500, "misconfigured", "Two-factor approval is not configured correctly."), of(signedIn));
    }
}
