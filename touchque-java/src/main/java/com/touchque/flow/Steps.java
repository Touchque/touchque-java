package com.touchque.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.Assurance;
import com.touchque.LoginDetail;
import com.touchque.RiskReason;
import com.touchque.TouchqueApiException;
import com.touchque.TouchqueApprovalMismatchException;
import com.touchque.TouchqueClient;
import com.touchque.TouchqueConfigException;
import com.touchque.crypto.Details;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import com.touchque.resources.Login;
import com.touchque.resources.LoginRequestOptions;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The headless step-up flow shared by every integration: start, show the step in YOUR UI, check,
 * complete exactly once. Use it through {@link TouchqueClient#start}, {@link TouchqueClient#check}
 * and {@link TouchqueClient#complete}.
 */
public final class Steps {
    private static final Map<String, String> STATE_MAP = Map.of("PENDING", "waiting", "CONFIRMED", "approved", "REJECTED", "rejected", "EXPIRED", "expired");
    private static final DateTimeFormatter ISO_MILLIS = new DateTimeFormatterBuilder().appendInstant(3).toFormatter(Locale.ROOT);

    private Steps() {
    }

    public static Step start(TouchqueClient client, String action, StartOptions o) {
        if (o.user == null || o.user.isEmpty()) throw new TouchqueConfigException("start() needs the user id");
        List<LoginDetail> norm = Details.normalize(o.details);
        List<LoginDetail> details = norm.isEmpty() ? null : norm;
        try {
            Login.RequestResult res = client.login().request(new LoginRequestOptions(o.user).type(action).referenceId(o.referenceId)
                    .clientIp(o.ip).userAgent(o.userAgent).details(details).browserProof(o.browserProof).context(o.context));
            List<RiskReason> reasons = null;
            if (res.reasons() != null && !res.reasons().isEmpty()) {
                reasons = new ArrayList<>();
                for (RiskReason r : res.reasons()) reasons.add(new RiskReason(r.code(), r.text(), null));
            }
            String canaryUrl = Json.str(res.canary(), "url");
            Step.Canary canary = canaryUrl == null || canaryUrl.isEmpty() ? null : new Step.Canary(canaryUrl);
            String caseCode = emptyToNull(res.caseCode());
            if (res.requiresPasskey()) {
                return new Step("passkey_required", res.requestId(), null, res.expiresAt(), details, caseCode, reasons, null, canary, null, null, null, null, null);
            }
            // telemetryToken only when the workspace collects behavioural signals; the canary only on this first step.
            return new Step("waiting", res.requestId(), emptyToNull(res.challengeCode()), res.expiresAt(), details, caseCode, reasons,
                    emptyToNull(res.telemetryToken()), canary, null, null, null, null, null);
        } catch (TouchqueApiException e) {
            String code = e.code() != null ? e.code() : e.error();
            String caseCode = e.caseCode();
            String message = String.valueOf(e.getMessage()).toLowerCase(Locale.ROOT);
            if (e.status() == 404 && ("device_not_linked".equals(code) || message.contains("linked device"))) {
                return o.enroll ? enrollStep(client, o.user) : Step.of("enroll");
            }
            if (e.status() == 423) return Step.of("frozen").withRetryAfter(e.retryAfter()).withCaseCode(caseCode);
            if (e.status() == 429) return Step.of("rate_limited").withRetryAfter(e.retryAfter()).withCaseCode(caseCode);
            if (e.status() == 400 && ("unknown_action".equals(code) || message.contains("invalid action type"))) {
                throw new TouchqueConfigException("Unknown action \"" + action + "\". Create it once with tq.actionTypes().define(\"" + action
                        + "\", ...) or in the dashboard (Action Types).");
            }
            if (e.status() == 403) {
                String reason = "blocked".equals(code) ? e.reason() : null;
                if (reason == null && ("passkey_not_registered".equals(code) || "phishing_resistant_required".equals(e.error()))) reason = "passkey_not_registered";
                if (reason == null && "action_disabled".equals(code)) reason = "action_disabled";
                if (reason == null) reason = code != null ? code : "blocked";
                return Step.of("blocked").withReason(reason).withCaseCode(caseCode);
            }
            throw e;
        }
    }

    /** First-time linking. Never unlinks a phone: a secret is only re-issued when the account is confirmed NOT linked. */
    private static Step enrollStep(TouchqueClient client, String user) {
        try {
            JsonNode gen = client.auth().generateSecret(user);
            return Step.of("enroll").withEnroll(enroll(gen));
        } catch (TouchqueApiException e) {
            if (e.status() != 409) throw e;
            JsonNode current = null;
            try {
                current = client.auth().getUser(user);
            } catch (TouchqueApiException ignored) {
                // unknown user: reset below
            }
            if (current != null && (Json.bool(current, "used") || emptyToNull(Json.str(current, "deviceId")) != null)) {
                return Step.of("enroll").withReason("already_linked");
            }
            return Step.of("enroll").withEnroll(enroll(client.auth().resetSecret(user)));
        }
    }

    private static Step.Enroll enroll(JsonNode res) {
        List<String> codes = null;
        JsonNode rc = res.get("recoveryCodes");
        if (rc != null && rc.isArray()) {
            codes = new ArrayList<>();
            for (JsonNode c : rc) codes.add(c.asText());
        }
        // When the QR stops working: the API's expiresAt when it is ISO 8601, else now + ttlMs, else unknown.
        String expiresAt = Json.str(res, "expiresAt");
        if (epochMillis(expiresAt) == null) {
            Long ttl = Json.lng(res, "ttlMs");
            expiresAt = ttl != null && ttl > 0 ? iso(System.currentTimeMillis() + ttl) : null;
        }
        return new Step.Enroll(Json.str(res, "qrCodeDataUrl"), codes, expiresAt);
    }

    /** An ISO 8601 date-time with an offset ({@code Z} or {@code +03:00}) in ms since the epoch, or null. */
    static Long epochMillis(String iso) {
        if (iso == null || iso.isEmpty()) return null;
        try {
            return OffsetDateTime.parse(iso).toInstant().toEpochMilli();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /** ms since the epoch as ISO 8601 in UTC with milliseconds, like JavaScript's toISOString. */
    static String iso(long epochMillis) {
        return ISO_MILLIS.format(Instant.ofEpochMilli(epochMillis));
    }

    public static Step check(TouchqueClient client, String requestId) {
        Login.Status s = client.login().status(requestId);
        String state = "PENDING".equals(s.status()) && s.requiresPasskey() ? "passkey_required" : STATE_MAP.getOrDefault(String.valueOf(s.status()), "waiting");
        Step step = Step.of(state).withRequestId(requestId);
        return "approved".equals(state) ? step.withAssurance(s.assurance()) : step;
    }

    public static Approval complete(TouchqueClient client, String requestId, CompleteExpectations expect) {
        JsonNode res = client.login().consume(requestId);
        String externalUsername = Json.str(res, "externalUsername");
        boolean sameUser = externalUsername != null && externalUsername.equalsIgnoreCase(expect.user());
        boolean sameDetails = Details.digest(expect.details()).equals(Details.digest(Details.fromJson(res.get("details"))));
        // An empty referenceId is never sent, so the API holds none: "" and null are the same transaction.
        boolean sameRef = java.util.Objects.equals(emptyToNull(Json.str(res, "referenceId")), emptyToNull(expect.referenceId()));
        if (!sameUser || !String.valueOf(Json.str(res, "type")).equals(expect.action()) || !sameDetails || !sameRef) {
            throw new TouchqueApprovalMismatchException("this approval is for a different user, action or transaction.");
        }
        JsonNode provisional = res.get("provisional");
        Boolean prov = provisional != null && provisional.isBoolean() ? provisional.booleanValue() : null;
        return new Approval(requestId, externalUsername, Json.str(res, "type"), TouchqueHttp.to(res.get("assurance"), Assurance.class),
                Json.str(res, "confirmedVia"), res.get("approvalProof") instanceof ObjectNode p ? p : null, prov,
                prov == null ? null : Json.bool(res, "revoked"), Json.str(res, "revokeReason"), Json.str(res, "reconfirmedAt"), null);
    }

    // ── Guard token ─────────────────────────────────────────────────────────
    // The browser echoes it back while it waits. Signed with a key derived from the API secret, it
    // binds the approval to one user, action and transaction.

    private static byte[] tokenKey(String apiSecret) {
        return Crypto.hmacSha256(apiSecret.getBytes(StandardCharsets.UTF_8), "touchque-guard-token-v1".getBytes(StandardCharsets.UTF_8));
    }

    public static String signGuardToken(String apiSecret, ObjectNode claims) {
        String body = Base64Url.encode(Json.write(claims));
        return "v1." + body + "." + Base64Url.encode(Crypto.hmacSha256(tokenKey(apiSecret), body.getBytes(StandardCharsets.US_ASCII)));
    }

    /** The token's claims, or null when it is not one of ours, was changed or expired. */
    public static ObjectNode verifyGuardToken(String apiSecret, String token) {
        if (token == null || token.isEmpty() || token.length() > 4096) return null;
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || !parts[0].equals("v1")) return null;
        String expected = Base64Url.encode(Crypto.hmacSha256(tokenKey(apiSecret), parts[1].getBytes(StandardCharsets.US_ASCII)));
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII), parts[2].getBytes(StandardCharsets.US_ASCII))) return null;
        byte[] bytes = Base64Url.tryDecode(parts[1]);
        if (bytes == null) return null;
        JsonNode claims = Json.parse(new String(bytes, StandardCharsets.UTF_8));
        Long exp = Json.lng(claims, "exp");
        if (!(claims instanceof ObjectNode c) || exp == null || exp < System.currentTimeMillis()) return null;
        return c;
    }

    /** A step as the JSON the browser gets (camelCase, nulls left out). */
    public static JsonNode toJson(Step step) {
        return Json.toNodeWithoutNulls(step);
    }

    static String emptyToNull(String s) {
        return s == null || s.isEmpty() ? null : s;
    }
}
