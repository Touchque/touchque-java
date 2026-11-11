package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.LoginDetail;
import com.touchque.TouchqueApiException;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.function.Supplier;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** Offline Sign: QR challenge and typed-code approvals that work with the phone offline. */
public final class Offline {
    private static final String CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private final TouchqueHttp http;

    /** Internal: use {@code tq.offline()}. */
    public Offline(TouchqueHttp http) {
        this.http = http;
    }

    /** An offline QR challenge's settings. */
    public static final class ChallengeOptions {
        private final String externalUsername;
        private String type = "LOGIN";
        private List<LoginDetail> details;
        private String clientIp;
        private String userAgent;
        private Integer ttlSeconds;
        private boolean includeQrImage = true;
        private String requestId;
        private boolean requireNumberMatch;

        public ChallengeOptions(String externalUsername) {
            this.externalUsername = externalUsername;
        }

        public ChallengeOptions type(String v) {
            this.type = v;
            return this;
        }

        /** Required for critical action types. */
        public ChallengeOptions details(List<LoginDetail> v) {
            this.details = v;
            return this;
        }

        public ChallengeOptions clientIp(String v) {
            this.clientIp = v;
            return this;
        }

        public ChallengeOptions userAgent(String v) {
            this.userAgent = v;
            return this;
        }

        /** 30-300 (default 120). */
        public ChallengeOptions ttlSeconds(Integer v) {
            this.ttlSeconds = v;
            return this;
        }

        /** False: no {@code qrDataUrl} image, only the {@code qr} text. */
        public ChallengeOptions includeQrImage(boolean v) {
            this.includeQrImage = v;
            return this;
        }

        /** The push this QR is a fallback for: a phone-side rejection then kills the QR. */
        public ChallengeOptions requestId(String v) {
            this.requestId = v;
            return this;
        }

        public ChallengeOptions requireNumberMatch(boolean v) {
            this.requireNumberMatch = v;
            return this;
        }
    }

    /**
     * Issues an offline QR challenge. With number matching the answer has {@code challengeCode}:
     * print it under the QR; the phone offers it among two decoys.
     */
    public JsonNode challenge(ChallengeOptions o) {
        ObjectNode body = Json.object().put("externalUsername", o.externalUsername).put("type", o.type == null || o.type.isEmpty() ? "LOGIN" : o.type);
        if (o.details != null) body.set("details", LoginRequestOptions.detailsJson(o.details));
        Json.put(body, "clientIp", o.clientIp);
        Json.put(body, "userAgent", o.userAgent);
        Json.put(body, "ttlSeconds", o.ttlSeconds);
        if (!o.includeQrImage) body.put("includeQrImage", false);
        Json.put(body, "requestId", o.requestId);
        if (o.requireNumberMatch) body.put("requireNumberMatch", true);
        return http.post("/offline/challenge", body);
    }

    /**
     * Verifies the 7-character code the phone shows. Never throws for a wrong, expired or used
     * code: check {@code approved}; {@code reason} is invalid_code, locked, expired, used,
     * unknown_challenge, request_rejected, too_many_failures or device_not_enrolled.
     */
    public JsonNode verify(String challengeId, String code) {
        return notApprovedAsResult(() -> http.post("/offline/verify", Json.object().put("challengeId", challengeId).put("code", code)));
    }

    /**
     * Verifies the rolling time-based code (no QR scan needed). Refused for critical action types.
     * {@code requestId}: the push this sign-in belongs to; a code is refused (request_rejected) once
     * the phone rejected it.
     */
    public JsonNode verifyTotp(String externalUsername, String code, String type, String clientIp, String requestId) {
        ObjectNode body = Json.object().put("externalUsername", externalUsername).put("code", code).put("type", type == null ? "LOGIN" : type);
        Json.put(body, "clientIp", clientIp);
        Json.put(body, "requestId", requestId);
        return notApprovedAsResult(() -> http.post("/offline/totp/verify", body));
    }

    /**
     * For checking typed time-based codes while your server cannot reach Touchque (an outage):
     * salted, slow digests of each user's next codes, never a key. Up to 1,000 users and 24,000
     * user-steps a call; {@code steps} 1-480 (default 480, four hours). Check a code with
     * {@link #matchTotpVerifier}. Requires the workspace policies offlineTotpEnabled and outageVerifiersEnabled.
     */
    public JsonNode totpVerifiers(List<String> externalUsernames, Long fromStep, Integer steps) {
        ArrayNode users = Json.array();
        externalUsernames.forEach(users::add);
        ObjectNode body = Json.object();
        body.set("externalUsernames", users);
        Json.put(body, "fromStep", fromStep);
        Json.put(body, "steps", steps);
        return http.post("/offline/totp/verifiers", body);
    }

    /**
     * Checks a typed code against one user's digests without calling Touchque: the step the code
     * belongs to (the current one or one either side), or null. Accept each step once: remember the
     * step you accepted and refuse codes for it or an older one.
     *
     * @param verifiers the answer of {@link #totpVerifiers}
     * @param user      one element of its {@code users}
     * @param at        the time to check at (null: now)
     */
    public static Long matchTotpVerifier(JsonNode verifiers, JsonNode user, String code, Instant at) {
        String given = code.toUpperCase(Locale.ROOT).replace(" ", "").replace("-", "").replace("\t", "");
        Long stepSeconds = Json.lng(verifiers, "stepSeconds");
        if (given.length() != 7 || given.chars().anyMatch(c -> CODE_ALPHABET.indexOf(c) < 0) || stepSeconds == null || stepSeconds <= 0) return null;
        byte[] salt;
        byte[] digests;
        try {
            salt = Base64.getDecoder().decode(String.valueOf(Json.str(user, "salt")));
            digests = Base64.getDecoder().decode(String.valueOf(Json.str(user, "digests")));
        } catch (IllegalArgumentException e) {
            return null;
        }
        JsonNode kdf = verifiers.get("kdf");
        Integer length = Json.integer(kdf, "length");
        Integer iterations = Json.integer(kdf, "iterations");
        Long fromStep = Json.lng(user, "fromStep");
        Long notAfter = Json.lng(verifiers, "notAfterStep");
        if (length == null || length <= 0 || iterations == null || fromStep == null || notAfter == null) return null;
        long now = (at != null ? at : Instant.now()).getEpochSecond() / stepSeconds;
        for (long step : new long[] {now, now - 1, now + 1}) {
            if (step < fromStep || step > notAfter) continue;
            int i = (int) (step - fromStep) * 2 * length;
            if (i + 2 * length > digests.length) continue;
            byte[] stepSalt = concat(salt, (":" + step).getBytes(StandardCharsets.UTF_8));
            byte[] got = pbkdf2(given, stepSalt, iterations, length);
            if (MessageDigest.isEqual(Arrays.copyOfRange(digests, i, i + length), got)
                    || MessageDigest.isEqual(Arrays.copyOfRange(digests, i + length, i + 2 * length), got)) {
                return step;
            }
        }
        return null;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] pbkdf2(String password, byte[] salt, int iterations, int length) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, length * 8);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static JsonNode notApprovedAsResult(Supplier<JsonNode> call) {
        try {
            return call.get();
        } catch (TouchqueApiException e) {
            if (e.status() >= 500) throw e;
            ObjectNode out = Json.object().put("approved", false);
            String reason = e.reason() != null ? e.reason() : e.code() != null ? e.code() : e.error();
            Json.put(out, "reason", reason);
            Json.put(out, "attemptsLeft", e.attemptsLeft());
            return out;
        }
    }
}
