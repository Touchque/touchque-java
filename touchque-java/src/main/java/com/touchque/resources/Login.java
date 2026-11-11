package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.Assurance;
import com.touchque.LoginDetail;
import com.touchque.RiskReason;
import com.touchque.TouchqueConfigException;
import com.touchque.TouchqueNetworkException;
import com.touchque.TouchquePasskeyRequiredException;
import com.touchque.TouchqueRejectedException;
import com.touchque.TouchqueTimeoutException;
import com.touchque.internal.Json;
import com.touchque.internal.SdkLog;
import com.touchque.internal.TouchqueHttp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/** Push approvals on the user's phone: request, status, wait, use once, report fraud. */
public final class Login {
    /** Reasons accepted by {@link #reportFraud}. */
    public static final List<String> FRAUD_REASONS = List.of("chargeback", "account_takeover", "social_engineering", "other");

    private final TouchqueHttp http;

    /** Internal: use {@code tq.login()}. */
    public Login(TouchqueHttp http) {
        this.http = http;
    }

    /** A push to the user's phone (returns at once; see {@link #verify} to wait). */
    public RequestResult request(String externalUsername) {
        return request(new LoginRequestOptions(externalUsername));
    }

    /**
     * A push to the user's phone with every option: transaction details, the end user's IP and
     * browser, number matching, the browser proof of silent sign-ins, context for your Actions,
     * security changes, a destination, a QR pairing. With behavioral biometrics on, the answer has
     * {@code telemetryToken} for the {@code @touchque/web} widget.
     */
    public RequestResult request(LoginRequestOptions options) {
        return TouchqueHttp.to(http.post("/login/request", options.toJson()), RequestResult.class);
    }

    /** Where a request is now: PENDING, CONFIRMED, REJECTED or EXPIRED. */
    public Status status(String requestId) {
        return TouchqueHttp.to(http.get("/login/status/" + TouchqueHttp.seg(requestId)), Status.class);
    }

    /** Asks the phone and waits for the answer. */
    public VerifyResult verify(String externalUsername) {
        return verify(new LoginRequestOptions(externalUsername));
    }

    /**
     * Asks the phone and polls until the user approves or rejects. With number matching (your
     * option, a workspace policy, a critical action or the risk engine) the user picks a number on
     * the phone: {@code onChallenge} runs right after the request exists and before any waiting.
     *
     * @throws TouchquePasskeyRequiredException only a passkey can approve (policy), or the user tapped Approve during a call (step_up)
     * @throws TouchqueRejectedException the user rejected it
     * @throws TouchqueTimeoutException it expired or the timeout passed
     */
    public VerifyResult verify(LoginRequestOptions options) {
        RequestResult sent = TouchqueHttp.to(http.post("/login/request", options.toJson(false)), RequestResult.class);
        if (sent.requiresPasskey()) throw new TouchquePasskeyRequiredException(sent.requestId(), "policy");
        if (options.onChallenge() != null) {
            try {
                options.onChallenge().accept(new VerifyChallenge(sent.requestId(), emptyToNull(sent.challengeCode()), sent.expiresAt(), sent.reasons(), sent.caseCode()));
            } catch (RuntimeException e) {
                // The caller's callback must not stop the wait.
                http.log().warn("[Touchque] onChallenge failed: " + SdkLog.describe(e));
            }
        }
        return waitFor(sent.requestId(), sent.challengeCode(),
                options.timeout() != null ? options.timeout() : Duration.ofSeconds(30),
                options.pollInterval() != null ? options.pollInterval() : Duration.ofMillis(400));
    }

    /** Waits for a request you already sent (e.g. with {@link #request}). Null durations take the defaults (30 s, 400 ms). */
    public VerifyResult waitForApproval(String requestId, Duration timeout, Duration pollInterval) {
        return waitFor(requestId, null, timeout != null ? timeout : Duration.ofSeconds(30), pollInterval != null ? pollInterval : Duration.ofMillis(400));
    }

    private VerifyResult waitFor(String requestId, String challengeCode, Duration timeout, Duration interval) {
        Instant deadline = Instant.now().plus(timeout);
        while (true) {
            Status s = status(requestId);
            switch (String.valueOf(s.status())) {
                case "CONFIRMED":
                    // Vishing Shield: approved during a call; critical actions wait for the phone to re-confirm.
                    return new VerifyResult(true, s.status(), requestId, emptyToNull(challengeCode), s.assurance(), s.confirmedVia(), s.provisional());
                case "REJECTED":
                    throw new TouchqueRejectedException(requestId);
                case "EXPIRED":
                    throw new TouchqueTimeoutException("Touchque: request '" + requestId + "' expired before it was approved.", requestId);
                default:
                    break;
            }
            // Vishing Shield: tapped during a call, the request now waits for a passkey in the browser.
            if ("PENDING".equals(s.status()) && s.requiresPasskey()) throw new TouchquePasskeyRequiredException(requestId, "step_up");
            if (Instant.now().plus(interval).isAfter(deadline)) {
                throw new TouchqueTimeoutException("Touchque: request '" + requestId + "' was not approved within " + timeout.toSeconds()
                        + "s. The user did not respond in time.", requestId);
            }
            sleep(interval);
        }
    }

    static void sleep(Duration d) {
        try {
            Thread.sleep(d.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TouchqueNetworkException("interrupted", e);
        }
    }

    static String emptyToNull(String s) {
        return s == null || s.isEmpty() ? null : s;
    }

    /** Approves a pending request with one of the user's recovery codes (no phone). */
    public JsonNode approveWithRecoveryCode(String requestId, String code) {
        return http.post("/login/recovery", Json.object().put("requestId", requestId).put("code", code));
    }

    /**
     * Uses an approved request exactly once. The first call on a CONFIRMED request wins
     * atomically; every later call (a replayed token, a retried form post) throws
     * {@link com.touchque.TouchqueApiException} with code {@code already_used} (409). The answer
     * has {@code approvalProof}, the phone's signature over what it showed, when the phone has a
     * hardware key.
     */
    public JsonNode consume(String requestId) {
        return http.post("/login/" + TouchqueHttp.seg(requestId) + "/consume", Json.object());
    }

    /**
     * Reports a request you later learned was fraud (a chargeback, a confirmed account takeover, a
     * scam the user was talked into). The risk engine learns from it and the report is kept in your
     * audit log; the request's status does not change. A repeat answers {@code alreadyReported: true}.
     *
     * @param reason one of {@link #FRAUD_REASONS} (null: other)
     * @param note   free text for your audit log, at most 500 characters
     */
    public JsonNode reportFraud(String requestId, String reason, String note) {
        if (requestId == null || requestId.isEmpty()) throw new TouchqueConfigException("reportFraud() needs the request id");
        ObjectNode body = Json.object();
        Json.put(body, "reason", reason);
        Json.put(body, "note", note);
        return http.post("/login/" + TouchqueHttp.seg(requestId) + "/report-fraud", body);
    }

    /** What {@code onChallenge} receives as soon as the request exists. {@code challengeCode} is the number to show, or null. */
    public record VerifyChallenge(String requestId, String challengeCode, String expiresAt, List<RiskReason> reasons, String caseCode) {
    }

    /**
     * The answer of {@code POST /login/request}. {@code challengeCode}: the number to show with
     * number matching. {@code caseCode}: the "Why?" code of this decision. {@code requiresPasskey}:
     * a phishing-resistant policy demands a passkey, no push was sent. {@code destination}:
     * {@code {known, lookalike}} when you sent one.
     */
    public record RequestResult(String requestId, String challengeCode, String message, String expiresAt, String caseCode,
                                List<RiskReason> reasons, boolean requiresPasskey, String telemetryToken, JsonNode canary, JsonNode destination) {
    }

    /**
     * Where a request is: {@code status} PENDING, CONFIRMED, REJECTED or EXPIRED. {@code provisional}:
     * Vishing Shield, approved during a call and waiting for the phone to re-confirm.
     */
    public record Status(String status, String externalUsername, String type, String referenceId, List<LoginDetail> details, boolean consumed,
                         boolean requiresPasskey, String confirmedVia, Assurance assurance, String rejectReason, boolean provisional,
                         String reconfirmedAt, boolean revoked, String revokeReason, JsonNode reply) {
    }

    /** An approved request: {@code provisional} means approved during a call (critical actions wait for the phone to re-confirm). */
    public record VerifyResult(boolean approved, String status, String requestId, String challengeCode, Assurance assurance,
                               String confirmedVia, boolean provisional) {
    }
}
