package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;

/** Setup secrets (the QR code the Touchque app scans) and a user's link status. */
public final class Auth {
    private final TouchqueHttp http;

    /** Internal: use {@code tq.auth()}. */
    public Auth(TouchqueHttp http) {
        this.http = http;
    }

    /**
     * A new setup secret for a user: show {@code qrCodeDataUrl} so the Touchque app links the
     * phone. 409 when an unscanned or used secret exists ({@link #resetSecret} issues a new one).
     * Without the browser's IP and User-Agent the phone cannot show where the QR was asked for:
     * prefer {@link #generateSecret(String, String, String)} while handling a browser's request.
     */
    public JsonNode generateSecret(String externalUsername) {
        return generateSecret(externalUsername, null, null);
    }

    /**
     * {@link #generateSecret(String)} with the browser that asks for the QR: the END user's IP and
     * User-Agent, from the request as for a login request (each left out when null or empty).
     * Touchque keeps where the QR was asked for with the secret, never in the QR, and the phone
     * shows it before it links ({@link SetupContext}). Touchque cleans both itself (it drops a
     * port, ignores a loopback address or one that is not an IP, strips control characters from
     * the User-Agent and keeps its first 512) and never refuses the call over them.
     */
    public JsonNode generateSecret(String externalUsername, String clientIp, String userAgent) {
        return http.post("/auth/generate-secret", secretBody(externalUsername, clientIp, userAgent));
    }

    /**
     * Regenerates a user's secret. It sends no IP or User-Agent, so the new QR has no setup context
     * (the old QR's is dropped): prefer {@link #resetSecret(String, String, String)} while handling
     * a browser's request.
     */
    public JsonNode resetSecret(String externalUsername) {
        return resetSecret(externalUsername, null, null);
    }

    /**
     * {@link #resetSecret(String)} with the END user's IP and User-Agent, sent as
     * {@link #generateSecret(String, String, String)} sends them (each left out when null or empty).
     * Touchque records them with the new QR as generate does ({@link SetupContext}); when neither is
     * sent or usable, the new QR has none.
     */
    public JsonNode resetSecret(String externalUsername, String clientIp, String userAgent) {
        return http.post("/auth/secret/reset", secretBody(externalUsername, clientIp, userAgent));
    }

    /** {@code {externalUsername, clientIp?, userAgent?}}: the same rule as a login request, null and empty left out. */
    private static ObjectNode secretBody(String externalUsername, String clientIp, String userAgent) {
        ObjectNode body = Json.object().put("externalUsername", externalUsername);
        Json.put(body, "clientIp", clientIp);
        Json.put(body, "userAgent", userAgent);
        return body;
    }

    /**
     * Checks a setup secret code. This is the phone's call: the Touchque app makes it after it
     * scans the QR, and a valid code's answer carries {@code setupContext}, where that QR was asked
     * for, as the phone shows it before it links ({@link SetupContext#of} reads it from the answer,
     * {@link SetupContext#parse} from the raw value). Its {@code farFromPhone} compares that place
     * with the address that calls validate: when your server calls it, with your server, not the
     * phone.
     */
    public JsonNode validateSecret(String secret) {
        return http.post("/auth/secret/validate", Json.object().put("secret", secret));
    }

    /**
     * A user's link status without sending a push: {@code used} flips true and {@code deviceId} is
     * set once the app scans the secret. {@code device} is the linked phone's self-reported posture
     * (device trust: platform, OS, security patch, screen lock, jailbreak, hardware key,
     * attestation, {@code state} and {@code issues}), or null before a phone is linked. 404 for an
     * unknown user.
     */
    public JsonNode getUser(String externalUsername) {
        return http.get("/users/" + TouchqueHttp.seg(externalUsername));
    }

    /**
     * Where a first-time linking QR was asked for, as Touchque recorded it from the call that made
     * the QR ({@link Auth#generateSecret(String, String, String)} or
     * {@link Auth#resetSecret(String, String, String)}, with the IP and User-Agent you sent), never from
     * the QR itself. The phone shows it before it links, so a person tricked into scanning someone
     * else's QR sees that person's city and device. Every field may be null: {@code ip} (the
     * address the phone shows), {@code location} (from the IP), {@code device} (from the
     * User-Agent), {@code requestedAt} (ISO 8601, as the API sent it) and {@code farFromPhone}
     * (whether that place is far from the address that called validate: the phone's when the
     * Touchque app calls it, your server's when your server does; null when Touchque cannot tell).
     * {@link #of} reads it from a validate answer, {@link #parse} from the raw {@code setupContext}
     * value.
     */
    public record SetupContext(String ip, SetupLocation location, SetupDevice device, String requestedAt, Boolean farFromPhone) {
        /**
         * The {@code setupContext} of a {@link Auth#validateSecret} answer:
         * {@code parse(validateAnswer.get("setupContext"))}, so null when the answer is null, is
         * not an object or has none (see {@link #parse}).
         */
        public static SetupContext of(JsonNode validateAnswer) {
            return parse(validateAnswer == null ? null : validateAnswer.get("setupContext"));
        }

        /**
         * Reads a raw {@code setupContext} value, the field of a validate answer
         * ({@code answer.get("setupContext")}; {@link #of} takes the whole answer). Null when it is
         * null (Java or JSON), missing or not an object: nothing was recorded for that QR (its
         * request named no usable IP or User-Agent), or an older QR or server. Lenient: a field that
         * is missing, null or of the wrong type is null ({@code ip} and {@code requestedAt} only
         * strings, {@code farFromPhone} only a boolean, {@code location} and {@code device} only
         * objects, whose fields are read the same way, so one whose fields all have the wrong type
         * is an object of nulls); unknown fields are ignored; it never throws.
         */
        public static SetupContext parse(JsonNode raw) {
            if (raw == null || !raw.isObject()) return null;
            JsonNode location = raw.get("location");
            JsonNode device = raw.get("device");
            JsonNode far = raw.get("farFromPhone");
            return new SetupContext(Json.str(raw, "ip"),
                    location != null && location.isObject()
                            ? new SetupLocation(Json.str(location, "city"), Json.str(location, "country"), Json.str(location, "countryCode")) : null,
                    device != null && device.isObject()
                            ? new SetupDevice(Json.str(device, "browser"), Json.str(device, "os"), Json.str(device, "model")) : null,
                    Json.str(raw, "requestedAt"),
                    far != null && far.isBoolean() ? far.booleanValue() : null);
        }
    }

    /** Where the IP of a {@link SetupContext} is, e.g. Berlin, Germany, DE. Each field may be null. */
    public record SetupLocation(String city, String country, String countryCode) {
    }

    /** The browser that asked for the QR, from its User-Agent, e.g. Safari, iOS, iPhone ({@code model} when it names one). Each field may be null. */
    public record SetupDevice(String browser, String os, String model) {
    }
}
