package com.touchque.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.Assurance;
import com.touchque.LoginDetail;
import com.touchque.RiskReason;
import com.touchque.TouchQueApiException;
import com.touchque.TouchQueApprovalMismatchException;
import com.touchque.TouchQueClient;
import com.touchque.TouchQueConfigException;
import com.touchque.TouchQueNetworkException;
import com.touchque.crypto.Details;
import com.touchque.internal.Json;
import com.touchque.internal.SdkLog;
import com.touchque.resources.Offline;
import com.touchque.resources.Risk;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Framework-agnostic step-up guard (the Spring starter's {@code @RequireTouchQue} is a thin wrapper
 * over it). Contract, the same in every TouchQue server SDK:
 * <ul>
 * <li>1st request: 202 {@code {"touchque": step, "token": ...}}; show the step in your UI;</li>
 * <li>repeat with the token (header {@code X-TouchQue-Token}): 202 while waiting, then the protected action runs once;</li>
 * <li>refused: 403 / 408 / 423 / 429 {@code {"touchque": {"state": ...}}}.</li>
 * </ul>
 */
public final class Guard {
    public static final String TOKEN_HEADER = "X-TouchQue-Token";
    public static final String OFFLINE_HEADER = "X-TouchQue-Offline";
    public static final String CODE_HEADER = "X-TouchQue-Code";
    public static final String CODE_TYPE_HEADER = "X-TouchQue-Code-Type";
    public static final String BROWSER_HEADER = "X-TouchQue-Browser";

    private static final long TOKEN_TTL_MS = 10 * 60 * 1000;
    /** A real proof is a few hundred characters; anything far larger is not one. */
    private static final int MAX_BROWSER_PROOF = 4096;

    private static final Map<String, Integer> STATUS_OF = Map.of(
            "waiting", 202, "enroll", 202, "passkey_required", 202, "offline", 202,
            "approved", 200, "rejected", 403, "blocked", 403, "expired", 408, "frozen", 423, "rate_limited", 429);

    private static final Set<String> WAITING = Set.of("waiting", "passkey_required", "offline");

    private Guard() {
    }

    /** Silent sign-ins for a guard or relay: {@code maxAgeSeconds} is your own limit on how long ago the last phone approval in that browser may be (0 = always ask; null = TouchQue's). */
    public record SilentSignIn(Integer maxAgeSeconds) {
        public static SilentSignIn on() {
            return new SilentSignIn(null);
        }
    }

    /** One request through the guard. */
    public static final class Input {
        String user;
        final String action;
        List<LoginDetail> details;
        String referenceId;
        String ip;
        String userAgent;
        String token;
        boolean offline;
        String code;
        String codeType;
        boolean enroll = true;
        String browserProof;
        SilentSignIn silentSignIn;
        Map<String, Object> context;

        public Input(String user, String action) {
            this.user = user;
            this.action = action;
        }

        public Input details(List<LoginDetail> v) {
            this.details = v;
            return this;
        }

        public Input referenceId(String v) {
            this.referenceId = v;
            return this;
        }

        /** The end user's IP. */
        public Input ip(String v) {
            this.ip = v;
            return this;
        }

        public Input userAgent(String v) {
            this.userAgent = v;
            return this;
        }

        /** {@code X-TouchQue-Token}: the token from the last answer. */
        public Input token(String v) {
            this.token = v;
            return this;
        }

        /** {@code X-TouchQue-Offline: 1}: switch to offline approval. */
        public Input offline(boolean v) {
            this.offline = v;
            return this;
        }

        /** {@code X-TouchQue-Code}: the code from the phone. */
        public Input code(String v) {
            this.code = v;
            return this;
        }

        /** {@code X-TouchQue-Code-Type}: totp for the rolling time-based code. */
        public Input codeType(String v) {
            this.codeType = v;
            return this;
        }

        /** False: never show the first-time linking QR. */
        public Input enroll(boolean v) {
            this.enroll = v;
            return this;
        }

        /** {@code X-TouchQue-Browser}: the browser's device-bound key proof. */
        public Input browserProof(String v) {
            this.browserProof = v;
            return this;
        }

        /** Null: silent sign-ins off. */
        public Input silentSignIn(SilentSignIn v) {
            this.silentSignIn = v;
            return this;
        }

        /** For your TouchQue Actions only ({@code event.context}). */
        public Input context(Map<String, Object> v) {
            this.context = v;
            return this;
        }

        /** Reads the guard headers (token, offline switch, code, code type, browser proof) with a header getter. */
        public Input headers(java.util.function.Function<String, String> header) {
            this.token = header.apply(TOKEN_HEADER);
            this.offline = "1".equals(header.apply(OFFLINE_HEADER));
            this.code = header.apply(CODE_HEADER);
            this.codeType = header.apply(CODE_TYPE_HEADER);
            this.browserProof = header.apply(BROWSER_HEADER);
            return this;
        }
    }

    /**
     * The guard's answer: either {@code approved} (run your protected action once) or {@code status}
     * and {@code body} to send back as JSON. {@link #retryAfter()}: seconds for a Retry-After header
     * (frozen, rate limited).
     */
    public record Result(int status, Approval approved, ObjectNode body, Step step) {
        public Integer retryAfter() {
            return step != null && step.retryAfter() != null && step.retryAfter() > 0 ? step.retryAfter() : null;
        }
    }

    /**
     * True when this request only polls an approval already on its way: a valid token bound to this
     * user/action/details, still waiting, and no offline switch or typed code. It can only read the
     * status, so relays do not count it against the per-user push limit.
     */
    public static boolean isStatusPoll(TouchQueClient client, Input input) {
        if (empty(input.user) || empty(input.token) || input.offline || !empty(input.code)) return false;
        ObjectNode claims = Steps.verifyGuardToken(client.apiSecret(), input.token);
        if (claims == null || empty(Json.str(claims, "rid"))) return false;
        return bound(claims, input) && WAITING.contains(String.valueOf(Json.str(claims, "st")));
    }

    private static boolean bound(ObjectNode claims, Input input) {
        return java.util.Objects.equals(Json.str(claims, "u"), input.user) && java.util.Objects.equals(Json.str(claims, "a"), input.action)
                && java.util.Objects.equals(Json.str(claims, "d"), Details.digest(input.details)) && java.util.Objects.equals(Json.str(claims, "r"), input.referenceId);
    }

    /**
     * Runs one step of the guard. Silent sign-ins: with {@code silentSignIn} set, a new attempt that
     * carries a browser proof first asks TouchQue ({@code risk().check}); when it answers exactly
     * {@code prompt: false} the guard approves at once with no push ({@code assurance.method} silent,
     * {@code confirmedVia} SILENT, {@code requestId} silent). Otherwise, and on any error, the usual push starts.
     */
    public static Result run(TouchQueClient client, Input input) {
        if (empty(input.user)) {
            return error(401, Step.of("blocked").withReason("unauthenticated"), "unauthenticated", "Sign in first.");
        }
        String user = input.user;
        String action = input.action;
        List<LoginDetail> norm = Details.normalize(input.details);
        List<LoginDetail> details = norm.isEmpty() ? null : norm;
        String secret = client.apiSecret();
        try {
            ObjectNode claims = Steps.verifyGuardToken(secret, input.token);
            ObjectNode bound = claims != null && bound(claims, input) ? claims : null;
            String rid = bound == null ? null : Json.str(bound, "rid");
            String n = bound == null ? null : Json.str(bound, "n");
            String oc = bound == null ? null : Json.str(bound, "oc");
            String st = bound == null ? null : Json.str(bound, "st");
            ObjectNode keep = Json.object();
            putNullable(keep, "oc", oc);
            putNullable(keep, "rid", rid);
            putNullable(keep, "n", n);
            ObjectNode keepN = Json.object();
            putNullable(keepN, "n", n);

            // Offline: the user typed the code from the phone.
            if (bound != null && !empty(input.code) && ("offline".equals(st) || "totp".equals(input.codeType))) {
                boolean isTotp = "totp".equals(input.codeType);
                JsonNode res = isTotp
                        ? client.offline().verifyTotp(user, input.code, action, input.ip, rid)
                        : client.offline().verify(oc != null ? oc : "", input.code);
                String resUser = Json.str(res, "externalUsername");
                String resType = Json.str(res, "type");
                boolean forThis = (empty(resUser) || resUser.equalsIgnoreCase(user)) && (empty(resType) || resType.equals(action));
                String reason = Json.str(res, "reason");
                if (Json.bool(res, "approved") && forThis) {
                    return new Result(200, new Approval(oc != null ? oc : "offline-totp", user, action,
                            new Assurance(false, isTotp ? "offline_totp" : "offline_code"), isTotp ? "OFFLINE_TOTP" : "OFFLINE_CODE",
                            null, null, null, null, null, null), null, null);
                }
                if ("invalid_code".equals(reason) && !isTotp) {
                    return issue(secret, input, details, Step.of("offline").withOffline(new Step.Offline(oc != null ? oc : "", null, null, null, null, Json.integer(res, "attemptsLeft"))), keep);
                }
                if ("invalid_code".equals(reason)) return issue(secret, input, details, Step.of("offline").withReason("invalid_code"), keep);
                // The phone rejected the push this QR belongs to: the whole sign-in is over.
                if ("request_rejected".equals(reason)) return issue(secret, input, details, Step.of("rejected").withRequestId(rid).withReason("request_rejected"), null);
                // The push now waits for a passkey (Vishing Shield): no code may finish it.
                if ("passkey_required".equals(reason) && !empty(rid)) {
                    return issue(secret, input, details, Step.of("passkey_required").withRequestId(rid).withNumber(n), keepN);
                }
                return issue(secret, input, details, Step.of("expired".equals(reason) ? "expired" : "blocked").withReason(reason != null ? reason : "offline_failed"), null);
            }

            if (input.offline) {
                try {
                    // Tie the QR to the push it follows: a phone-side rejection kills it, and number matching carries over.
                    JsonNode ch = client.offline().challenge(new Offline.ChallengeOptions(user).type(action).details(details)
                            .clientIp(input.ip).userAgent(input.userAgent).requestId(rid));
                    JsonNode totp = ch.get("totpAvailable");
                    Step.Offline offline = new Step.Offline(Json.str(ch, "challengeId"), Json.str(ch, "qrDataUrl"), Json.str(ch, "expiresAt"),
                            totp != null && totp.isBoolean() ? totp.booleanValue() : null, Steps.emptyToNull(Json.str(ch, "challengeCode")), null);
                    ObjectNode extra = Json.object();
                    putNullable(extra, "rid", rid);
                    putNullable(extra, "n", offline.challengeCode() != null ? offline.challengeCode() : n);
                    return issue(secret, input, details, Step.of("offline").withOffline(offline), extra);
                } catch (TouchQueApiException e) {
                    String code = e.code() != null ? e.code() : e.error();
                    if (e.status() == 409 && "request_rejected".equals(code)) {
                        return issue(secret, input, details, Step.of("rejected").withRequestId(rid).withReason("request_rejected"), null);
                    }
                    // The push it would follow now waits for a passkey (Vishing Shield): no QR, run the passkey.
                    if (!empty(rid) && "passkey_required".equals(code)) {
                        return issue(secret, input, details, Step.of("passkey_required").withRequestId(rid).withNumber(n), keepN);
                    }
                    if (e.status() < 500) {
                        return issue(secret, input, details, Step.of("blocked").withReason(e.code() != null ? e.code() : e.error() != null ? e.error() : "offline_unavailable"), null);
                    }
                    throw e;
                }
            }

            // Waiting on a push / passkey, or showing the offline QR next to a push still open: poll, run once approved.
            if (bound != null && !empty(rid) && WAITING.contains(String.valueOf(st))) {
                Step now = Steps.check(client, rid);
                if ("approved".equals(now.state())) {
                    try {
                        Approval approval = Steps.complete(client, rid, new CompleteExpectations(user, action, input.details, input.referenceId));
                        return new Result(200, approval, null, null);
                    } catch (TouchQueApiException e) {
                        if (e.status() != 409) throw e;
                        return issue(secret, input, details, Step.of("expired").withReason(e.code() != null ? e.code() : "already_used"), null);
                    }
                }
                // The push behind the QR moved to a passkey after a tap during a call: the QR's code would be refused now.
                if ("offline".equals(st) && "passkey_required".equals(now.state())) {
                    return issue(secret, input, details, Step.of("passkey_required").withRequestId(rid).withNumber(n), keepN);
                }
                if ("offline".equals(st) && ("waiting".equals(now.state()) || "expired".equals(now.state()))) {
                    // Nothing changed for the user: keep showing the QR they have.
                    return issue(secret, input, details, Step.of("offline").withOffline(new Step.Offline(oc != null ? oc : "", null, null, null, null, null)), keep);
                }
                if ("waiting".equals(now.state()) || "passkey_required".equals(now.state())) {
                    // "Why?": the case code stays on screen while it waits.
                    return issue(secret, input, details, Step.of(now.state()).withRequestId(rid).withNumber(n).withCaseCode(Json.str(bound, "cc")), keepN);
                }
                return issue(secret, input, details, Step.of(now.state()).withRequestId(rid), null);
            }

            // Anything else (no or foreign token, enrollment finished, new attempt): start.
            String proof = !empty(input.browserProof) && input.browserProof.length() <= MAX_BROWSER_PROOF ? input.browserProof : null;
            if (proof != null && input.silentSignIn != null) {
                Approval silent = silentApproval(client, input, proof);
                if (silent != null) return new Result(200, silent, null, null);
            }
            Step step = Steps.start(client, action, new StartOptions(user).details(details).referenceId(input.referenceId).ip(input.ip)
                    .userAgent(input.userAgent).enroll(input.enroll).browserProof(proof).context(input.context));
            return issue(secret, input, details, step, null);
        } catch (TouchQueConfigException e) {
            client.http().log().error("[TouchQue] guard misconfigured: " + SdkLog.describe(e));
            return error(500, Step.of("blocked").withReason("misconfigured"), "misconfigured", "Two-factor approval is not configured correctly.");
        } catch (TouchQueNetworkException | TouchQueApiException | TouchQueApprovalMismatchException e) {
            // A mismatch after the approval was consumed is answered like the other SDKs' guards, never thrown at the framework.
            // An outage (network, 5xx) is not the SDK's problem; anything else is worth a line, like the Node guard.
            if (!(e instanceof TouchQueNetworkException) && !(e instanceof TouchQueApiException a && a.status() >= 500)) {
                client.http().log().error("[TouchQue] approval failed: " + SdkLog.describe(e));
            }
            return error(503, Step.of("blocked").withReason("unavailable"), "unavailable", "Two-factor approval is temporarily unavailable.");
        }
    }

    private static Result issue(String secret, Input input, List<LoginDetail> details, Step step, ObjectNode extra) {
        if (details != null && step.details() == null && !"blocked".equals(step.state())) step = step.withDetails(details);
        ObjectNode claims = Json.object();
        claims.put("u", input.user);
        claims.put("a", input.action);
        claims.put("d", Details.digest(input.details));
        putNullable(claims, "r", input.referenceId);
        claims.put("st", step.state());
        putNullable(claims, "rid", step.requestId());
        putNullable(claims, "n", step.number());
        putNullable(claims, "oc", step.offline() == null ? null : step.offline().challengeId());
        claims.put("exp", System.currentTimeMillis() + TOKEN_TTL_MS);
        if (step.caseCode() != null) claims.put("cc", step.caseCode());
        if (extra != null) {
            Iterator<Map.Entry<String, JsonNode>> it = extra.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> e = it.next();
                claims.set(e.getKey(), e.getValue() == null ? null : e.getValue().deepCopy());
            }
        }
        ObjectNode body = Json.object();
        body.set("touchque", Steps.toJson(step));
        body.put("token", Steps.signGuardToken(secret, claims));
        return new Result(STATUS_OF.get(step.state()), null, body, step);
    }

    private static Result error(int status, Step step, String code, String message) {
        ObjectNode body = Json.object();
        body.set("touchque", Steps.toJson(step));
        body.set("error", Json.object().put("code", code).put("message", message));
        return new Result(status, null, body, step);
    }

    /** Asks TouchQue whether this known browser may sign in without the phone. Fails closed: only an answer of exactly {@code prompt: false} approves. */
    private static Approval silentApproval(TouchQueClient client, Input input, String proof) {
        try {
            Risk.CheckResult res = client.risk().check(new Risk.CheckOptions(input.user).type(input.action).clientIp(input.ip).userAgent(input.userAgent)
                    .browserProof(proof).context(input.context != null && !input.context.isEmpty() ? input.context : null)
                    .maxAgeSeconds(input.silentSignIn.maxAgeSeconds()));
            if (res.prompt()) return null;
            // Nothing was sent to the phone; reasons say why TouchQue let this known browser in.
            List<RiskReason> reasons = res.reasons();
            return new Approval("silent", input.user, input.action, new Assurance(false, "silent"), "SILENT", null, null, null, null, null, reasons);
        } catch (RuntimeException e) {
            client.http().log().warn("[TouchQue] silent sign-in check failed, asking the phone: " + SdkLog.describe(e));
            return null;
        }
    }

    private static void putNullable(ObjectNode o, String key, String value) {
        if (value == null) o.putNull(key);
        else o.put(key, value);
    }

    private static boolean empty(String s) {
        return s == null || s.isEmpty();
    }
}
