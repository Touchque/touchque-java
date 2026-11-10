package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchQueConfigException;
import com.touchque.TouchQueRejectedException;
import com.touchque.TouchQueTimeoutException;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;
import java.time.Duration;
import java.time.Instant;

/**
 * Safe Guard: a Safe transaction approved on the approver's phone for TouchQueSafeGuard (the guard on your
 * Safe). You send the raw transaction; the phone gets the raw fields only, decodes them itself, shows its own
 * rows and signs, with a key only its biometrics unlock, a 105-byte approval of the hash it computed. TouchQue
 * never holds a key that can approve.
 * <ol>
 * <li>{@link #request} asks the phone (same pipeline as {@code login().request}: risk engine, push limit,
 * Vishing Shield, case code, always biometrics).</li>
 * <li>{@link #waitForApproval} (or poll {@link #status}) until the phone answered.</li>
 * <li>Check {@code safeTx.approval} yourself with {@link com.touchque.crypto.SafeApproval#verify}: it needs your
 * own transaction and the approver's key from the guard, not this answer.</li>
 * <li>Purpose {@code approve}: {@link com.touchque.crypto.SafeApproval#withApprovals} as the signatures of
 * {@code execTransaction}. {@code schedule}: send {@link com.touchque.crypto.SafeApproval#scheduleCall} to the
 * guard; the change runs once its waiting time is over.</li>
 * </ol>
 */
public final class SafeGuard {
    private final TouchQueHttp http;

    /** Internal: use {@code tq.safeGuard()}. */
    public SafeGuard(TouchQueHttp http) {
        this.http = http;
    }

    /** One approver's phone to ask. {@code type} is an action type from your dashboard. */
    public static final class RequestOptions {
        private final String externalUsername;
        private final String type;
        private final SafeTx safeTx;
        private String referenceId;
        private Integer expiresIn;
        private String clientIp;
        private String userAgent;

        public RequestOptions(String externalUsername, String type, SafeTx safeTx) {
            this.externalUsername = externalUsername;
            this.type = type;
            this.safeTx = safeTx;
        }

        /** Your own id for this transaction. */
        public RequestOptions referenceId(String v) {
            this.referenceId = v;
            return this;
        }

        /** Seconds, 30 to 300 (default 300: reading a transaction takes longer than a sign-in). */
        public RequestOptions expiresIn(Integer v) {
            this.expiresIn = v;
            return this;
        }

        public RequestOptions clientIp(String v) {
            this.clientIp = v;
            return this;
        }

        public RequestOptions userAgent(String v) {
            this.userAgent = v;
            return this;
        }
    }

    /**
     * Asks the approver's phone to approve a Safe transaction: {@code requestId}, {@code expiresAt},
     * {@code caseCode} and {@code safeTx} (TouchQue's own decoding: {@code class}, {@code flags},
     * {@code safeTxHash}, {@code governanceHash}, {@code rows}; the phone decodes for itself).
     */
    public JsonNode request(RequestOptions o) {
        if (o == null || o.externalUsername == null || o.externalUsername.isEmpty()) throw new TouchQueConfigException("safeGuard.request() needs externalUsername.");
        if (o.type == null || o.type.isEmpty()) throw new TouchQueConfigException("safeGuard.request() needs type: an action type from your dashboard.");
        if (o.safeTx == null) throw new TouchQueConfigException("safeGuard.request() needs a SafeTx.");
        ObjectNode body = Json.object().put("externalUsername", o.externalUsername).put("type", o.type);
        body.set("safeTx", o.safeTx.toJson());
        Json.put(body, "referenceId", o.referenceId);
        Json.put(body, "expiresIn", o.expiresIn);
        Json.put(body, "clientIp", o.clientIp);
        Json.put(body, "userAgent", o.userAgent);
        return http.post("/safe-guard/approvals", body);
    }

    /**
     * The request's status ({@code status}, {@code provisional}) and {@code safeTx}: {@code class}, {@code flags},
     * {@code safeTxHash}, {@code governanceHash}, {@code purpose} ({@code approve} or {@code schedule}),
     * {@code approverIndex} and, once approved, {@code approval} (105 bytes, 0x hex) and {@code expiresAt}.
     */
    public JsonNode status(String requestId) {
        if (requestId == null || requestId.isEmpty()) throw new TouchQueConfigException("safeGuard.status() needs a requestId.");
        return http.get("/safe-guard/approvals/" + TouchQueHttp.seg(requestId));
    }

    /**
     * Polls until the phone approved and returns the status with the approval. Null durations take the
     * defaults (5 minutes, the request's own life; 1.5 s).
     *
     * @throws TouchQueRejectedException the person said no
     * @throws TouchQueTimeoutException it expired or the timeout passed
     */
    public JsonNode waitForApproval(String requestId, Duration timeout, Duration pollInterval) {
        Duration limit = timeout != null ? timeout : Duration.ofMinutes(5);
        Duration interval = pollInterval != null ? pollInterval : Duration.ofMillis(1500);
        Instant deadline = Instant.now().plus(limit);
        while (true) {
            JsonNode s = status(requestId);
            switch (s.path("status").asText()) {
                case "CONFIRMED":
                    return s;
                case "REJECTED":
                    throw new TouchQueRejectedException(requestId);
                case "EXPIRED":
                    throw new TouchQueTimeoutException("TouchQue: request '" + requestId + "' expired before it was approved.", requestId);
                default:
                    break;
            }
            if (Instant.now().isAfter(deadline)) {
                throw new TouchQueTimeoutException("TouchQue: Safe Guard approval '" + requestId + "' was not given within " + limit.toSeconds() + "s.", requestId);
            }
            Login.sleep(interval);
        }
    }
}
