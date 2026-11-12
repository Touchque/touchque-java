package com.touchque.flow;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.Assurance;
import com.touchque.LoginDetail;
import com.touchque.RiskReason;
import com.touchque.TouchqueApiException;
import com.touchque.TouchqueApprovalMismatchException;
import com.touchque.TouchqueClient;
import com.touchque.TouchqueConfigException;
import com.touchque.TouchqueNetworkException;
import com.touchque.crypto.Details;
import com.touchque.internal.Json;
import com.touchque.internal.SdkLog;
import com.touchque.resources.Offline;
import com.touchque.resources.Risk;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Framework-agnostic step-up guard (the Spring starter's {@code @RequireTouchque} is a thin wrapper
 * over it). Contract, the same in every Touchque server SDK:
 * <ul>
 * <li>1st request: 202 {@code {"touchque": step, "token": ...}}; show the step in your UI;</li>
 * <li>repeat with the token (header {@code X-Touchque-Token}): 202 while waiting, then the protected action runs once;
 * a waiting poll repeats the request's {@code expiresAt};</li>
 * <li>while the first-time linking QR is up: 202 {@code {"touchque": {"state": "enroll", "expiresAt": ...}}} without
 * {@code enroll}, keep showing that QR; a new one comes with {@code enroll.qrCodeDataUrl} about 15 s before it expires;</li>
 * <li>refused: 403 / 408 / 423 / 429 {@code {"touchque": {"state": ...}}}.</li>
 * </ul>
 * {@link #response} turns a result that is not an approval into its HTTP answer.
 */
public final class Guard {
    public static final String TOKEN_HEADER = "X-Touchque-Token";
    public static final String OFFLINE_HEADER = "X-Touchque-Offline";
    public static final String CODE_HEADER = "X-Touchque-Code";
    public static final String CODE_TYPE_HEADER = "X-Touchque-Code-Type";
    public static final String BROWSER_HEADER = "X-Touchque-Browser";
    /** On every refused answer (status 400 or more): the step's state. */
    public static final String STATE_HEADER = "X-Touchque-State";
    /** On a refused answer whose step has a reason: that reason. */
    public static final String REASON_HEADER = "X-Touchque-Reason";

    private static final long TOKEN_TTL_MS = 10 * 60 * 1000;
    /** A first-time QR this close to its expiry is replaced instead of kept: the user could not scan it in time. */
    private static final long ENROLL_RENEW_MS = 15 * 1000;
    /** A real proof is a few hundred characters; anything far larger is not one. */
    private static final int MAX_BROWSER_PROOF = 4096;

    private static final Map<String, Integer> STATUS_OF = Map.of(
            "waiting", 202, "enroll", 202, "passkey_required", 202, "offline", 202,
            "approved", 200, "rejected", 403, "blocked", 403, "expired", 408, "frozen", 423, "rate_limited", 429);

    private static final Set<String> WAITING = Set.of("waiting", "passkey_required", "offline");
    /** A push or a passkey on its way: the steps whose polls repeat the request's expiry. */
    private static final Set<String> ON_THE_PHONE = Set.of("waiting", "passkey_required");

    /** The client of {@code run(null, …)}: built on first use, then kept (or set with {@link #setDefaultClient}). */
    private static volatile TouchqueClient sharedClient;
    private static final Object SHARED_CLIENT_LOCK = new Object();
    /** How {@link #defaultClient()} builds it: from the environment. Package-private so a test can make a build fail. */
    static volatile Supplier<TouchqueClient> clientBuilder = TouchqueClient::new;

    private Guard() {
    }

    /** Silent sign-ins for a guard or relay: {@code maxAgeSeconds} is your own limit on how long ago the last phone approval in that browser may be (0 = always ask; null = Touchque's). */
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
        Supplier<Optional<Result>> beforeStart;

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

        /** {@code X-Touchque-Token}: the token from the last answer. */
        public Input token(String v) {
            this.token = v;
            return this;
        }

        /** {@code X-Touchque-Offline: 1}: switch to offline approval. */
        public Input offline(boolean v) {
            this.offline = v;
            return this;
        }

        /** {@code X-Touchque-Code}: the code from the phone. */
        public Input code(String v) {
            this.code = v;
            return this;
        }

        /** {@code X-Touchque-Code-Type}: totp for the rolling time-based code. */
        public Input codeType(String v) {
            this.codeType = v;
            return this;
        }

        /**
         * False: never show the first-time linking QR. A user with no phone then gets 202
         * {@code {"state": "enroll", "reason": "enrollment_off"}}.
         */
        public Input enroll(boolean v) {
            this.enroll = v;
            return this;
        }

        /** {@code X-Touchque-Browser}: the browser's device-bound key proof. */
        public Input browserProof(String v) {
            this.browserProof = v;
            return this;
        }

        /** Null: silent sign-ins off. */
        public Input silentSignIn(SilentSignIn v) {
            this.silentSignIn = v;
            return this;
        }

        /** For your Touchque Actions only ({@code event.context}). */
        public Input context(Map<String, Object> v) {
            this.context = v;
            return this;
        }

        /**
         * Called at most once, only for the token of a first-time QR ({@code enroll} with its expiry),
         * right before the guard starts something instead of answering "keep the QR": a silent check
         * or a push once the phone is linked, or a new QR once the old one expired, is about to, or is
         * gone. A result is answered as it is and nothing starts. Relays charge the start here like a
         * fresh attempt, so a status poll never starts anything on the poll budget.
         */
        public Input beforeStart(Supplier<Optional<Result>> v) {
            this.beforeStart = v;
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

        /**
         * The headers of a refused answer (status 400 or more): {@code X-Touchque-State}, and
         * {@code X-Touchque-Reason} when the step has a reason; none otherwise. {@code @touchque/web}
         * reads the step from them when a body has no {@code touchque} (an errorBody's string, say).
         */
        public Map<String, String> refusalHeaders() {
            if (status < 400 || step == null || empty(step.state())) return Map.of();
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put(STATE_HEADER, step.state());
            if (!empty(step.reason())) headers.put(REASON_HEADER, step.reason());
            return headers;
        }
    }

    /**
     * A refused answer (status 400 or more), as an adapter's {@code errorBody} callback sees it.
     * {@code code}: {@code error.code} when the guard set one, else the step's reason, else its state.
     * {@code message}: {@code error.message} when set, else a sentence for the state.
     * {@code touchque}: the step as it would be sent.
     */
    public record Refusal(int status, String code, String message, JsonNode touchque) {
        /** The refusal in a guard's answer, or null for a 202 step or an approval. */
        public static Refusal of(Result result) {
            if (result == null || result.approved() != null || result.status() < 400 || result.body() == null) return null;
            JsonNode step = stepOf(result);
            JsonNode error = result.body().get("error");
            String state = Json.str(step, "state");
            String code = Json.str(error, "code");
            if (empty(code)) code = Json.str(step, "reason");
            if (empty(code)) code = state;
            String message = Json.str(error, "message");
            if (empty(message)) {
                message = switch (String.valueOf(state)) {
                    case "rejected" -> "The approval was rejected.";
                    case "expired" -> "The approval expired. Try again.";
                    case "frozen" -> "Too many rejected approvals. Try again later.";
                    case "rate_limited" -> "Too many attempts. Try again later.";
                    default -> "The approval was refused.";
                };
            }
            return new Refusal(result.status(), code, message, step == null ? null : step.deepCopy());
        }
    }

    /** The step a result answers: its body's {@code touchque}, else its {@link Result#step()} (a hook's result may carry only that). */
    private static JsonNode stepOf(Result result) {
        JsonNode step = result.body() == null ? null : result.body().get("touchque");
        return step != null || result.step() == null ? step : Steps.toJson(result.step());
    }

    /**
     * Your app's own JSON body for refused answers (status 400 or more: 401, 403, 408, 423, 429,
     * 500, 503). Never called for a 202 step or on approval. What it returns counts by its JSON
     * encoding: a JSON object is sent with {@code touchque} set to the step (so
     * {@code @touchque/web} still sees the state; no token is added), anything else (a string, a
     * number, a list, null) as it is. It gets a copy of the step. See {@link #response}.
     */
    @FunctionalInterface
    public interface ErrorBody {
        Object body(Refusal refusal);
    }

    /**
     * The HTTP answer of a guard result that is not an approval, as {@link #response} builds it:
     * the status, the headers ({@code Cache-Control: no-store}, {@code Retry-After} on 423 and 429,
     * {@code X-Touchque-State} and {@code X-Touchque-Reason} on a refusal) and the JSON body (an
     * object, or what an {@link ErrorBody} returned: a string, a number, a list, null). Send the
     * body as JSON.
     */
    public record Response(int status, Map<String, String> headers, JsonNode body) {
    }

    /**
     * What to send for a result that is not an approval: the status and headers
     * {@code @RequireTouchque} and the relay send (they use this too), and the guard's body.
     * {@code errorBody} (null: the guard's body) shapes the refusals, status 400 or more; it is
     * never called for a 202 step. This form writes its result with the SDK's own ObjectMapper and
     * logs nothing when it fails (the guard's body is sent then). For the answer
     * {@code @RequireTouchque} sends with an errorBody, written with your app's ObjectMapper and
     * logged, use {@link #response(Result, ErrorBody, ObjectMapper, System.Logger)}. Without an
     * errorBody the two forms are the same.
     *
     * @throws IllegalArgumentException for an approval: run your action instead
     */
    public static Response response(Result result, ErrorBody errorBody) {
        return response(result, errorBody, null, null);
    }

    /**
     * The answer {@code @RequireTouchque} sends: {@link #response(Result, ErrorBody)} with your
     * app's {@code mapper} writing what {@code errorBody} returns (null: the SDK's; it is read back
     * with the SDK's limits, so more than 1,000 levels of nesting fall back too), and a
     * {@code logger} for {@code [Touchque] errorBody failed: <message>} (null: nothing is logged).
     *
     * @throws IllegalArgumentException for an approval: run your action instead
     */
    public static Response response(Result result, ErrorBody errorBody, ObjectMapper mapper, System.Logger logger) {
        if (result == null || result.approved() != null) {
            throw new IllegalArgumentException("Guard.response answers a step or a refusal; on approval, run your action");
        }
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Cache-Control", "no-store");
        if (result.retryAfter() != null) headers.put("Retry-After", String.valueOf(result.retryAfter()));
        headers.putAll(result.refusalHeaders());
        return new Response(result.status(), Collections.unmodifiableMap(headers), body(result, errorBody, mapper, new SdkLog(logger, false)));
    }

    /** The guard's body, or for a refusal (400 or more) what {@code errorBody} makes of it. */
    private static JsonNode body(Result result, ErrorBody errorBody, ObjectMapper mapper, SdkLog log) {
        Refusal refusal = errorBody == null ? null : Refusal.of(result);
        if (refusal == null) return result.body();
        try {
            // Decided by the real encoding: written with the app's ObjectMapper and read back with the SDK's, so the
            // answer sent meets the same write and read limits (nesting depth, sizes). What cannot be written falls back below.
            Object value = errorBody.body(refusal);
            JsonNode node = value == null ? NullNode.instance : Json.MAPPER.readTree((mapper != null ? mapper : Json.MAPPER).writeValueAsBytes(value));
            JsonNode step = stepOf(result);
            // The SDK's key wins, so @touchque/web still sees the state.
            if (node instanceof ObjectNode object && step != null) object.set("touchque", step.deepCopy());
            return node != null ? node : NullNode.instance;
        } catch (Exception | StackOverflowError e) {
            // Checked exceptions too (a Kotlin lambda, @SneakyThrows), and a cycle in what it returned: the default body.
            // Jackson's own message, without the reference chain (it names the app's fields and can run to kilobytes).
            String message = e instanceof JsonProcessingException j ? j.getOriginalMessage() : e.getMessage();
            log.error("[Touchque] errorBody failed: " + (message != null ? message : e.getClass().getSimpleName()));
            return result.body();
        }
    }

    /**
     * True when this request only reads a state: it polls an approval already on its way (a valid
     * token bound to this user/action/details, still waiting) or a first-time linking QR still up (a
     * bound {@code enroll} token whose QR expires in more than 15 s), with no offline switch or typed
     * code. Relays do not count it against the per-user push limit. A start such a poll leads to (a
     * push once the phone is linked, a new QR) goes through {@link Input#beforeStart}, where relays
     * charge it like a fresh attempt: every start is counted. A null {@code client} is
     * {@link #defaultClient()}; while that cannot be built, false.
     */
    public static boolean isStatusPoll(TouchqueClient client, Input input) {
        if (empty(input.user) || empty(input.token) || input.offline || !empty(input.code)) return false;
        if (client == null) client = defaultClientOrNull();
        if (client == null) return false;
        ObjectNode claims = Steps.verifyGuardToken(client.apiSecret(), input.token);
        if (claims == null || !bound(claims, input)) return false;
        String st = Json.str(claims, "st");
        if ("enroll".equals(st)) return qrStillUp(Json.lng(claims, "ee"));
        return !empty(Json.str(claims, "rid")) && WAITING.contains(String.valueOf(st));
    }

    /** A first-time QR that expires at {@code ee} (ms since the epoch) can still be scanned: more than 15 s left. */
    private static boolean qrStillUp(Long ee) {
        return ee != null && System.currentTimeMillis() < ee - ENROLL_RENEW_MS;
    }

    /**
     * The guard's answer when no client can be built (TQ_API_KEY / TQ_API_SECRET missing): 401
     * {@code unauthenticated} without a user, else 500 {@code misconfigured}. An adapter that builds
     * its client on first use answers this instead of throwing.
     */
    public static Result withoutClient(Input input) {
        return empty(input.user) ? unauthenticated() : misconfigured();
    }

    /**
     * The client {@link #run} and {@link #isStatusPoll} use when you pass null: the one
     * {@link #setDefaultClient} set, else one built from {@code TQ_API_KEY}, {@code TQ_API_SECRET}
     * and {@code TQ_API_URL} on first use and kept. A build that fails is not kept: the next call
     * tries again. Thread-safe. It is not the Spring Boot starter's bean: that one also reads
     * {@code touchque.*}. Call it at startup to fail fast: the guard's null-client path answers 500
     * {@code misconfigured} and logs nothing, while this throws and names the problem.
     *
     * @throws TouchqueConfigException while it cannot be built (no key or secret, say)
     */
    public static TouchqueClient defaultClient() {
        TouchqueClient c = sharedClient;
        if (c != null) return c;
        synchronized (SHARED_CLIENT_LOCK) {
            if (sharedClient == null) sharedClient = clientBuilder.get();
            return sharedClient;
        }
    }

    /**
     * Replaces the client {@code run(null, …)} and {@code isStatusPoll(null, …)} use, process-wide:
     * a client built with a logger gives that path its log lines. {@code null} forgets it, so the
     * next call builds one from the environment again.
     */
    public static void setDefaultClient(TouchqueClient client) {
        synchronized (SHARED_CLIENT_LOCK) {
            sharedClient = client;
        }
    }

    /** {@link #defaultClient()}, or null while it cannot be built. */
    private static TouchqueClient defaultClientOrNull() {
        try {
            return defaultClient();
        } catch (TouchqueConfigException e) {
            return null;
        }
    }

    private static boolean bound(ObjectNode claims, Input input) {
        return java.util.Objects.equals(Json.str(claims, "u"), input.user) && java.util.Objects.equals(Json.str(claims, "a"), input.action)
                && java.util.Objects.equals(Json.str(claims, "d"), Details.digest(input.details)) && java.util.Objects.equals(Json.str(claims, "r"), input.referenceId);
    }

    /**
     * Runs one step of the guard. Silent sign-ins: with {@code silentSignIn} set, a new attempt that
     * carries a browser proof first asks Touchque ({@code risk().check}); when it answers exactly
     * {@code prompt: false} the guard approves at once with no push ({@code assurance.method} silent,
     * {@code confirmedVia} SILENT, {@code requestId} silent). Otherwise, and on any error, the usual push starts.
     * First-time linking: a poll with the token of an {@code enroll} step only reads the link state
     * ({@code auth().getUser}). Not linked yet and the QR good for more than 15 s: 202
     * {@code {"state": "enroll", "expiresAt": ...}} without {@code enroll}, so the page keeps its QR.
     * Linked: the push starts. Expired or about to (15 s before): a new QR, with new recovery codes.
     * Waiting: every poll carries the request's {@code expiresAt}: the status answer's (a Vishing
     * Shield escalation extends it), else the one the token kept.
     * A null {@code client} is {@link #defaultClient()}. While that cannot be built: 401
     * {@code unauthenticated} without a user, else 500 {@code misconfigured}; nothing is logged then,
     * since the SDK's logger belongs to a client (call {@link #defaultClient()} at startup to fail fast).
     */
    public static Result run(TouchqueClient client, Input input) {
        if (empty(input.user)) return unauthenticated();
        if (client == null) client = defaultClientOrNull();
        if (client == null) return misconfigured();
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
            // When the push or passkey request expires (rx, ms since the epoch): its polls repeat it.
            Long rx = bound == null ? null : Json.lng(bound, "rx");
            String requestExpiresAt = rx == null ? null : Steps.iso(rx);
            ObjectNode keep = Json.object();
            putNullable(keep, "oc", oc);
            putNullable(keep, "rid", rid);
            putNullable(keep, "n", n);
            if (rx != null) keep.put("rx", rx);
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
                    return issue(secret, input, details, Step.of("passkey_required").withRequestId(rid).withNumber(n).withExpiresAt(requestExpiresAt), keepN);
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
                    if (rx != null) extra.put("rx", rx);
                    return issue(secret, input, details, Step.of("offline").withOffline(offline), extra);
                } catch (TouchqueApiException e) {
                    String code = e.code() != null ? e.code() : e.error();
                    if (e.status() == 409 && "request_rejected".equals(code)) {
                        return issue(secret, input, details, Step.of("rejected").withRequestId(rid).withReason("request_rejected"), null);
                    }
                    // The push it would follow now waits for a passkey (Vishing Shield): no QR, run the passkey.
                    if (!empty(rid) && "passkey_required".equals(code)) {
                        return issue(secret, input, details, Step.of("passkey_required").withRequestId(rid).withNumber(n).withExpiresAt(requestExpiresAt), keepN);
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
                // The live expiry: the status answer's when it parses (an escalation to a passkey extends it), else rx.
                // The token re-issued below keeps the one used.
                Long live = Steps.epochMillis(now.expiresAt());
                if (live != null) {
                    requestExpiresAt = now.expiresAt();
                    keep.put("rx", live);
                }
                if ("approved".equals(now.state())) {
                    try {
                        Approval approval = Steps.complete(client, rid, new CompleteExpectations(user, action, input.details, input.referenceId));
                        return new Result(200, approval, null, null);
                    } catch (TouchqueApiException e) {
                        if (e.status() != 409) throw e;
                        return issue(secret, input, details, Step.of("expired").withReason(e.code() != null ? e.code() : "already_used"), null);
                    }
                }
                // The push behind the QR moved to a passkey after a tap during a call: the QR's code would be refused now.
                if ("offline".equals(st) && "passkey_required".equals(now.state())) {
                    return issue(secret, input, details, Step.of("passkey_required").withRequestId(rid).withNumber(n).withExpiresAt(requestExpiresAt), keepN);
                }
                if ("offline".equals(st) && ("waiting".equals(now.state()) || "expired".equals(now.state()))) {
                    // Nothing changed for the user: keep showing the QR they have.
                    return issue(secret, input, details, Step.of("offline").withOffline(new Step.Offline(oc != null ? oc : "", null, null, null, null, null)), keep);
                }
                if ("waiting".equals(now.state()) || "passkey_required".equals(now.state())) {
                    // "Why?": the case code stays on screen while it waits.
                    return issue(secret, input, details, Step.of(now.state()).withRequestId(rid).withNumber(n).withCaseCode(Json.str(bound, "cc"))
                            .withExpiresAt(requestExpiresAt), keepN);
                }
                return issue(secret, input, details, Step.of(now.state()).withRequestId(rid), null);
            }

            // The first-time linking QR is up (its token carries the QR's expiry, ee): one QR per enrollment, not one per poll.
            Long ee = bound == null || !"enroll".equals(st) ? null : Json.lng(bound, "ee");
            if (ee != null) {
                JsonNode current;
                try {
                    current = client.auth().getUser(user);
                } catch (TouchqueApiException e) {
                    if (e.status() != 404) throw e;
                    current = null; // no such user: the QR is gone, a new one below
                }
                boolean linked = current != null && (Json.bool(current, "used") || !empty(Json.str(current, "deviceId")));
                if (current != null && !linked && qrStillUp(ee)) {
                    // Nothing changed for the user: the page keeps the QR and recovery codes it shows.
                    return issue(secret, input, details, Step.of("enroll").withExpiresAt(Steps.iso(ee)), Json.object().put("ee", ee));
                }
                // Linked: the push starts below. Not linked, and the QR expired or is about to: a new QR below.
                // Either way something starts: the caller may charge it, or answer instead.
                if (input.beforeStart != null) {
                    Optional<Result> instead = input.beforeStart.get();
                    if (instead != null && instead.isPresent()) return instead.get();
                }
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
        } catch (TouchqueConfigException e) {
            client.http().log().error("[Touchque] guard misconfigured: " + SdkLog.describe(e));
            return misconfigured();
        } catch (TouchqueNetworkException | TouchqueApiException | TouchqueApprovalMismatchException e) {
            // A mismatch after the approval was consumed is answered like the other SDKs' guards, never thrown at the framework.
            // An outage (network, 5xx) is not the SDK's problem; anything else is worth a line, like the Node guard.
            if (!(e instanceof TouchqueNetworkException) && !(e instanceof TouchqueApiException a && a.status() >= 500)) {
                client.http().log().error("[Touchque] approval failed: " + SdkLog.describe(e));
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
        // A push or passkey on its way: its polls repeat when the request expires (rx, ms since the epoch).
        Long rx = ON_THE_PHONE.contains(step.state()) ? Steps.epochMillis(step.expiresAt()) : null;
        if (rx != null) claims.put("rx", rx);
        // A first-time QR: its polls keep it until it expires (ee, ms since the epoch).
        Long ee = step.enroll() == null || empty(step.enroll().qrCodeDataUrl()) ? null : Steps.epochMillis(step.enroll().expiresAt());
        if (ee != null) claims.put("ee", ee);
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

    private static Result unauthenticated() {
        return error(401, Step.of("blocked").withReason("unauthenticated"), "unauthenticated", "Sign in first.");
    }

    private static Result misconfigured() {
        return error(500, Step.of("blocked").withReason("misconfigured"), "misconfigured", "Two-factor approval is not configured correctly.");
    }

    /** Asks Touchque whether this known browser may sign in without the phone. Fails closed: only an answer of exactly {@code prompt: false} approves. */
    private static Approval silentApproval(TouchqueClient client, Input input, String proof) {
        try {
            Risk.CheckResult res = client.risk().check(new Risk.CheckOptions(input.user).type(input.action).clientIp(input.ip).userAgent(input.userAgent)
                    .browserProof(proof).context(input.context != null && !input.context.isEmpty() ? input.context : null)
                    .maxAgeSeconds(input.silentSignIn.maxAgeSeconds()));
            if (res.prompt()) return null;
            // Nothing was sent to the phone; reasons say why Touchque let this known browser in.
            List<RiskReason> reasons = res.reasons();
            return new Approval("silent", input.user, input.action, new Assurance(false, "silent"), "SILENT", null, null, null, null, null, reasons);
        } catch (RuntimeException e) {
            client.http().log().warn("[Touchque] silent sign-in check failed, asking the phone: " + SdkLog.describe(e));
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
