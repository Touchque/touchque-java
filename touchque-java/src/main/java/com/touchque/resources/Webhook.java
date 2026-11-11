package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueWebhookReplayException;
import com.touchque.TouchqueWebhookSignatureException;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/** Webhook signature verification (signed with your API secret). */
public final class Webhook {
    /** Default replay window: a callback whose signed timestamp is further than this from now is rejected. */
    public static final int DEFAULT_TOLERANCE_SECONDS = 300;

    // reason values of a REJECTED login webhook. Treat a value you do not know as a rejection.
    public static final String REASON_USER_REJECTED = "user_rejected";
    /** The user said "this wasn't me": 2FA is frozen. */
    public static final String REASON_USER_REPORTED_FRAUD = "user_reported_fraud";
    /** The user said someone on the phone told them to approve: 2FA is frozen; treat it as a takeover in progress. */
    public static final String REASON_USER_REPORTED_COACHED = "user_reported_coached";
    /** An AI agent's request: the user said no and blocked the agent from asking them again (no 2FA freeze). */
    public static final String REASON_USER_BLOCKED_AGENT = "user_blocked_agent";
    public static final String REASON_RISK_REVERSED = "risk_reversed";
    public static final String REASON_RISK_STEP_UP = "risk_step_up";
    public static final String REASON_APPROVAL_SIGNATURE_INVALID = "approval_signature_invalid";
    public static final String REASON_DEVICE_INTEGRITY_FAILED = "device_integrity_failed";
    /** Vishing Shield: approved during a call (or with the screen shared / remote-controlled), critical, no passkey. */
    public static final String REASON_VISHING_SUSPECTED = "vishing_suspected";
    /** Mirror Alarm: the sign-in page was not on your site (a real-time phishing proxy). */
    public static final String REASON_PHISHING_ORIGIN = "phishing_origin";

    // event values of event webhooks. Ignore types you do not know.
    public static final String EVENT_DEVICE_LINKED = "DEVICE_LINKED";
    public static final String EVENT_DEVICE_UNLINKED = "DEVICE_UNLINKED";
    public static final String EVENT_PASSKEY_REGISTERED = "PASSKEY_REGISTERED";
    public static final String EVENT_PASSKEY_DELETED = "PASSKEY_DELETED";
    /** Device risk: an identification or a deviceRisk().check raised a signal that asks for more. Never a trait. */
    public static final String EVENT_DEVICE_RISK_SIGNAL = "DEVICE_RISK_SIGNAL";
    /** Device risk: an alert rule of the workspace went off. */
    public static final String EVENT_DEVICE_RISK_ALERT = "DEVICE_RISK_ALERT";
    /** After the call, the user confirmed a provisional approval was theirs: critical actions are allowed again. */
    public static final String EVENT_APPROVAL_RECONFIRMED = "APPROVAL_RECONFIRMED";
    /** The user took an approval back (reason COACHED or UNDO): end the session built on it. */
    public static final String EVENT_APPROVAL_REVOKED = "APPROVAL_REVOKED";
    /** Mobile SDK: send this push with your own keys ({@link Mobile#pushFromWebhook}). */
    public static final String EVENT_MOBILE_PUSH = "MOBILE_PUSH";
    // Never Locked Out (tq.recovery()): every event carries recoveryId and status.
    /** A recovery started (required, elevated, reasons); it waits for the new phone to scan the QR you show the user. */
    public static final String EVENT_RECOVERY_STARTED = "RECOVERY_STARTED";
    /** The new phone bound itself to the case with that QR: the vouchers and the old phone are asked now. */
    public static final String EVENT_RECOVERY_DEVICE_BOUND = "RECOVERY_DEVICE_BOUND";
    /** Enough vouchers approved: the move happens at coolOffUntil unless the old phone, a voucher or you veto it. */
    public static final String EVENT_RECOVERY_COOLING = "RECOVERY_COOLING";
    /** The account moved to the new phone (method vouch or old_phone); by vouch, critical actions are refused until probationUntil. */
    public static final String EVENT_RECOVERY_COMPLETED = "RECOVERY_COMPLETED";
    /** Someone stopped the recovery (reason, by). */
    public static final String EVENT_RECOVERY_VETOED = "RECOVERY_VETOED";
    public static final String EVENT_RECOVERY_EXPIRED = "RECOVERY_EXPIRED";
    /** The recovery ended without moving the account (reason). */
    public static final String EVENT_RECOVERY_FAILED = "RECOVERY_FAILED";
    // Help desk (tq.assist()): a session's events carry assistId, agentRef and agentName.
    /** IT started working on the person's account. */
    public static final String EVENT_ASSIST_OPENED = "ASSIST_OPENED";
    public static final String EVENT_ASSIST_ENDED = "ASSIST_ENDED";
    /** The person approved the check on their phone. */
    public static final String EVENT_ASSIST_CHECK_PASSED = "ASSIST_CHECK_PASSED";
    /** The check failed (outcome wrong_number, not_me, coached or declined); it carries a case code. */
    public static final String EVENT_ASSIST_CHECK_FAILED = "ASSIST_CHECK_FAILED";
    /** The help desk unfroze the person's approvals after a check on the phone. */
    public static final String EVENT_ASSIST_UNFROZEN = "ASSIST_UNFROZEN";
    /** The person checked that the agent from IT is really working on the account. */
    public static final String EVENT_ASSIST_CLAIM_CONFIRMED = "ASSIST_CLAIM_CONFIRMED";
    /** Nobody from IT was working on the account: someone is pretending to be IT. Only a case code: there is no session. */
    public static final String EVENT_ASSIST_CLAIM_UNVERIFIED = "ASSIST_CLAIM_UNVERIFIED";
    public static final String EVENT_AGENT_CREATED = "AGENT_CREATED";
    /** An AI agent was suspended (through the API or the dashboard): its tokens stopped working. */
    public static final String EVENT_AGENT_SUSPENDED = "AGENT_SUSPENDED";
    public static final String EVENT_AGENT_RESUMED = "AGENT_RESUMED";
    public static final String EVENT_AGENT_REVOKED = "AGENT_REVOKED";
    public static final String EVENT_AGENT_KEY_ADDED = "AGENT_KEY_ADDED";
    /** A key was removed from an AI agent; tokens bound to it stopped working. */
    public static final String EVENT_AGENT_KEY_REMOVED = "AGENT_KEY_REMOVED";
    /** The kill switch stopped every AI agent of the workspace. */
    public static final String EVENT_AGENTS_PAUSED = "AGENTS_PAUSED";
    public static final String EVENT_AGENTS_RESUMED = "AGENTS_RESUMED";
    public static final String EVENT_AGENT_POLICY_CHANGED = "AGENT_POLICY_CHANGED";
    /** The workspace's agent policy (every agent's floor) changed. */
    public static final String EVENT_AGENT_WORKSPACE_POLICY_CHANGED = "AGENT_WORKSPACE_POLICY_CHANGED";
    public static final String EVENT_AGENT_APPROVAL_REDEEMED = "AGENT_APPROVAL_REDEEMED";
    /** A person stopped an AI agent from asking them ("this wasn't me", coached, three rejections, or Block this agent). */
    public static final String EVENT_AGENT_BLOCKED_BY_PERSON = "AGENT_BLOCKED_BY_PERSON";
    public static final String EVENT_AGENT_UNBLOCKED_FOR_PERSON = "AGENT_UNBLOCKED_FOR_PERSON";
    /** An AI agent sent the same request to the same person three times in 10 minutes. */
    public static final String EVENT_AGENT_LOOP_DETECTED = "AGENT_LOOP_DETECTED";
    public static final String EVENT_AGENT_MANDATE_REQUESTED = "AGENT_MANDATE_REQUESTED";
    public static final String EVENT_AGENT_MANDATE_REVOKED = "AGENT_MANDATE_REVOKED";
    /** An AI agent's text carried an instruction to the model or a link that carries data; the request was refused. */
    public static final String EVENT_AGENT_INJECTION_SUSPECTED = "AGENT_INJECTION_SUSPECTED";
    /** An approval came back sooner than a person can answer; it is never usable. */
    public static final String EVENT_AGENT_INHUMAN_APPROVAL = "AGENT_INHUMAN_APPROVAL";
    /** A new or renamed AI agent's name read like another agent's; it was refused. */
    public static final String EVENT_AGENT_LOOKALIKE_NAME = "AGENT_LOOKALIKE_NAME";

    /**
     * Storage for webhook {@code jti}s already accepted. {@link #checkAndSet} must atomically record the
     * jti for the TTL and return true when it was NOT seen before. Use {@link MemoryReplayCache} for one
     * process, or implement it over Redis ({@code SET key 1 NX EX ttl}) or your database when you run
     * several instances.
     */
    public interface ReplayCache {
        boolean checkAndSet(String jti, Duration ttl);

        /**
         * Forgets a jti {@link #checkAndSet} recorded, so the same delivery is handled again when Touchque
         * retries it (your handler failed on it). Over Redis, {@code DEL key}. The default keeps the jti:
         * a retry of a delivery your handler failed on is then answered as a duplicate.
         */
        default void release(String jti) {
        }
    }

    /** An in-process {@link ReplayCache}: entries expire after their TTL; the map is capped. */
    public static final class MemoryReplayCache implements ReplayCache {
        private final ConcurrentHashMap<String, Instant> seen = new ConcurrentHashMap<>();
        private final int maxEntries;

        public MemoryReplayCache() {
            this(100_000);
        }

        public MemoryReplayCache(int maxEntries) {
            this.maxEntries = Math.max(2, maxEntries);
        }

        @Override
        public synchronized boolean checkAndSet(String jti, Duration ttl) {
            Instant now = Instant.now();
            Instant exp = seen.get(jti);
            if (exp != null && exp.isAfter(now)) return false;
            if (seen.size() >= maxEntries) {
                seen.entrySet().removeIf(e -> !e.getValue().isAfter(now));
                int drop = Math.max(0, seen.size() - maxEntries * 9 / 10);
                Iterator<String> keys = seen.keySet().iterator();
                List<String> victims = new ArrayList<>();
                while (keys.hasNext() && victims.size() < drop) victims.add(keys.next());
                victims.forEach(seen::remove);
            }
            seen.put(jti, now.plus(ttl));
            return true;
        }

        @Override
        public synchronized void release(String jti) {
            if (jti != null) seen.remove(jti);
        }
    }

    private final String secret;

    /** Internal: use {@code tq.webhook()}. */
    public Webhook(String apiSecret) {
        this.secret = apiSecret;
    }

    /**
     * Verifies an incoming webhook (signature, signed timestamp within {@code toleranceSeconds}, and
     * with a replay cache its {@code jti}) and returns its payload.
     *
     * @param rawBody          the raw request body, exactly as received
     * @param signature        the {@code x-signature} header; null uses the {@code signature} field inside the body
     * @param toleranceSeconds reject a callback whose signed timestamp is missing, invalid or further than this from now; 0 disables the check
     * @param replayCache      when set, a second delivery of the same jti throws {@link TouchqueWebhookReplayException}
     * @throws TouchqueWebhookSignatureException not from Touchque, changed, or too old
     */
    public ObjectNode verify(String rawBody, String signature, int toleranceSeconds, ReplayCache replayCache) {
        ObjectNode payload = verify(rawBody, signature, toleranceSeconds);
        if (replayCache != null) {
            String jti = Json.str(payload, "jti");
            if (jti == null || jti.isEmpty()) throw new TouchqueWebhookSignatureException("jti is missing");
            // Remember it for twice the window so it outlives any timestamp that could still pass the freshness check.
            Duration ttl = Duration.ofSeconds(Math.max(toleranceSeconds * 2L, 600));
            if (!replayCache.checkAndSet(jti, ttl)) throw new TouchqueWebhookReplayException(jti);
        }
        return payload;
    }

    /** Verifies the signature and the freshness (5 minutes) of a webhook, without a replay cache. */
    public ObjectNode verify(String rawBody, String signature) {
        return verify(rawBody, signature, DEFAULT_TOLERANCE_SECONDS);
    }

    /** Verifies the signature and the freshness of a webhook (no replay cache) and returns its payload. */
    public ObjectNode verify(String rawBody, String signature, int toleranceSeconds) {
        JsonNode parsed = Json.parse(rawBody);
        if (!(parsed instanceof ObjectNode payload)) throw new TouchqueWebhookSignatureException("invalid JSON payload");
        String provided = signature == null || signature.isEmpty() ? Json.str(payload, "signature") : signature;
        if (provided == null || provided.isEmpty()) throw new TouchqueWebhookSignatureException("no signature provided");
        String canonical;
        try {
            canonical = canonicalize(rawBody);
        } catch (IllegalArgumentException e) {
            throw new TouchqueWebhookSignatureException("could not canonicalize the payload");
        }
        String expected = Crypto.hmacHex(secret, canonical);
        // Never put the expected signature in the exception: it would be a signing oracle.
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII), provided.getBytes(StandardCharsets.UTF_8))) {
            throw new TouchqueWebhookSignatureException("invalid signature");
        }
        // Touchque always signs a timestamp: a missing or unparseable one fails closed.
        if (toleranceSeconds > 0) {
            Instant at = parseTime(Json.str(payload, "timestamp"));
            if (at == null) throw new TouchqueWebhookSignatureException("timestamp is missing or invalid");
            if (Math.abs(Duration.between(at, Instant.now()).toMillis()) > toleranceSeconds * 1000L) {
                throw new TouchqueWebhookSignatureException("timestamp is outside the allowed window");
            }
        }
        return payload;
    }

    /** An ISO 8601 time (with or without an offset; without one, UTC), or null. */
    public static Instant parseTime(String s) {
        if (s == null) return null;
        try {
            return OffsetDateTime.parse(s).toInstant();
        } catch (DateTimeParseException e) {
            try {
                return LocalDateTime.parse(s).toInstant(ZoneOffset.UTC);
            } catch (DateTimeParseException e2) {
                return null;
            }
        }
    }

    /**
     * The server's stableStringify: drop {@code signature}, sort the TOP-LEVEL keys only (by UTF-16
     * code units, like JavaScript), and keep each value's bytes (nested key order, number spelling);
     * insignificant whitespace is removed.
     */
    public static String canonicalize(String rawBody) {
        TreeMap<String, String> members = new TreeMap<>();
        for (Map.Entry<String, String> e : Json.topLevelMembers(rawBody).entrySet()) {
            if (!e.getKey().equals("signature")) members.put(e.getKey(), Json.compact(e.getValue()));
        }
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : members.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append(Json.jsString(e.getKey())).append(':').append(e.getValue());
        }
        return sb.append('}').toString();
    }
}
