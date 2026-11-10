package com.touchque.flow;

import com.touchque.Assurance;
import com.touchque.LoginDetail;
import com.touchque.RiskReason;
import java.util.List;

/**
 * What the user has to see while an approval runs, safe to send to the browser as JSON (it never
 * holds a secret). States: waiting, approved, rejected, expired, enroll, passkey_required, offline,
 * blocked, frozen, rate_limited. {@code number}: the number to show, the user picks it on the phone.
 * {@code caseCode}: the "Why?" code ("Tell your support team: K7P-2QX"). {@code canary}: Mirror Alarm,
 * the page showing this first step loads it. {@code enroll}: first-time linking, show its QR.
 * {@code offline}: the offline QR (the phone has no internet).
 */
public record Step(String state, String requestId, String number, String expiresAt, List<LoginDetail> details, String caseCode,
                   List<RiskReason> reasons, String telemetryToken, Canary canary, Enroll enroll, Offline offline, String reason,
                   Integer retryAfter, Assurance assurance) {

    /** Mirror Alarm: a tiny image your sign-in page loads, so a phishing proxy in front of your site gets the approval refused. */
    public record Canary(String url) {
    }

    /** First-time linking: show {@code qrCodeDataUrl}. */
    public record Enroll(String qrCodeDataUrl, List<String> recoveryCodes, String expiresAt) {
    }

    /** The offline QR: {@code challengeCode} is the number to print under it with number matching. */
    public record Offline(String challengeId, String qrDataUrl, String expiresAt, Boolean totpAvailable, String challengeCode, Integer attemptsLeft) {
    }

    /** A step with only a state. */
    public static Step of(String state) {
        return new Step(state, null, null, null, null, null, null, null, null, null, null, null, null, null);
    }

    public Step withRequestId(String v) {
        return new Step(state, v, number, expiresAt, details, caseCode, reasons, telemetryToken, canary, enroll, offline, reason, retryAfter, assurance);
    }

    public Step withNumber(String v) {
        return new Step(state, requestId, v, expiresAt, details, caseCode, reasons, telemetryToken, canary, enroll, offline, reason, retryAfter, assurance);
    }

    public Step withDetails(List<LoginDetail> v) {
        return new Step(state, requestId, number, expiresAt, v, caseCode, reasons, telemetryToken, canary, enroll, offline, reason, retryAfter, assurance);
    }

    public Step withCaseCode(String v) {
        return new Step(state, requestId, number, expiresAt, details, v, reasons, telemetryToken, canary, enroll, offline, reason, retryAfter, assurance);
    }

    public Step withEnroll(Enroll v) {
        return new Step(state, requestId, number, expiresAt, details, caseCode, reasons, telemetryToken, canary, v, offline, reason, retryAfter, assurance);
    }

    public Step withOffline(Offline v) {
        return new Step(state, requestId, number, expiresAt, details, caseCode, reasons, telemetryToken, canary, enroll, v, reason, retryAfter, assurance);
    }

    public Step withReason(String v) {
        return new Step(state, requestId, number, expiresAt, details, caseCode, reasons, telemetryToken, canary, enroll, offline, v, retryAfter, assurance);
    }

    public Step withRetryAfter(Integer v) {
        return new Step(state, requestId, number, expiresAt, details, caseCode, reasons, telemetryToken, canary, enroll, offline, reason, v, assurance);
    }

    public Step withAssurance(Assurance v) {
        return new Step(state, requestId, number, expiresAt, details, caseCode, reasons, telemetryToken, canary, enroll, offline, reason, retryAfter, v);
    }
}
