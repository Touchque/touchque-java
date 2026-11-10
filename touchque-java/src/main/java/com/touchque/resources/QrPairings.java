package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchQueConfigException;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Pairing a browser by QR code: your page shows a QR code, the person scans it with the TouchQue
 * app, and the phone that scanned is the one asked to approve.
 * <ol>
 * <li>Your page gets the thumbprint of its browser key ({@code @touchque/web} {@code browserKey.thumbprint()})
 * and sends it to your server.</li>
 * <li>{@link #create} registers a pairing and returns {@code uri} ({@code touchque://pair-browser?…}): show
 * it as a QR code. It can be scanned once, for {@code ttlSeconds} (default 120). The nonce in it never
 * leaves your server and the QR: TouchQue keeps only its hash.</li>
 * <li>Poll {@link #get}: {@code scanned} once a phone holding one of your users' accounts read it
 * ({@code externalUsername}, {@code proximity}), {@code confirmed} once the person went on,
 * {@code reported} when they said someone told them to scan it (their 2FA freezes).</li>
 * <li>{@code login().request(new LoginRequestOptions(user).qrPairing(id))} asks that phone, once, with
 * number matching; the browser key's fingerprint is one of the rows the phone signs. When your own
 * checks say no, {@link #refuse}, and the phone shows why.</li>
 * </ol>
 */
public final class QrPairings {
    /** What {@link #refuse} may tell the phone. */
    public static final List<String> REFUSAL_REASONS = List.of("policy", "device_not_approved", "too_many_browsers", "rate_limited", "no_account", "other");

    private static final Pattern B64URL_43 = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    private final TouchQueHttp http;

    /** Internal: use {@code tq.qrPairings()}. */
    public QrPairings(TouchQueHttp http) {
        this.http = http;
    }

    /** What the QR code says: {@code touchque://pair-browser?v=1&p=<pairing>&n=<nonce>&k=<key thumbprint>}. */
    public static String uri(String pairingId, String nonce, String keyThumbprint) {
        return "touchque://pair-browser?v=1&p=" + TouchQueHttp.seg(pairingId) + "&n=" + TouchQueHttp.seg(nonce) + "&k=" + TouchQueHttp.seg(keyThumbprint);
    }

    /** A pairing to register for one browser. */
    public static final class CreateOptions {
        private final String keyThumbprint;
        private String clientIp;
        private String userAgent;
        private String browser;
        private String os;
        private Integer ttlSeconds;

        /** @param keyThumbprint RFC 7638 thumbprint of the browser's key, base64url */
        public CreateOptions(String keyThumbprint) {
            this.keyThumbprint = keyThumbprint;
        }

        /** The end user's IP: the phone is told where the browser is and whether it is on the same network. */
        public CreateOptions clientIp(String v) {
            this.clientIp = v;
            return this;
        }

        public CreateOptions userAgent(String v) {
            this.userAgent = v;
            return this;
        }

        /** A short name the phone shows, e.g. "Chrome 155". */
        public CreateOptions browser(String v) {
            this.browser = v;
            return this;
        }

        /** E.g. "macOS 15". */
        public CreateOptions os(String v) {
            this.os = v;
            return this;
        }

        /** How long the QR code can be scanned: 30 to 300 seconds (default 120). */
        public CreateOptions ttlSeconds(Integer v) {
            this.ttlSeconds = v;
            return this;
        }
    }

    /** A registered pairing: show {@code uri} as a QR code. {@code nonce} is the one-time nonce in it (TouchQue keeps its SHA-256). */
    public record Created(String pairingId, String expiresAt, String nonce, String uri) {
    }

    /** Registers a pairing for one browser and returns the QR code's text. */
    public Created create(CreateOptions o) {
        if (o.keyThumbprint == null || !B64URL_43.matcher(o.keyThumbprint).matches()) {
            throw new TouchQueConfigException("qrPairings.create() needs keyThumbprint: the RFC 7638 thumbprint of the browser key, base64url (43 characters).");
        }
        if (o.ttlSeconds != null && (o.ttlSeconds < 30 || o.ttlSeconds > 300)) throw new TouchQueConfigException("qrPairings.create(): ttlSeconds must be 30 to 300.");
        String nonce = Base64Url.encode(Crypto.randomBytes(32));
        ObjectNode body = Json.object().put("nonceHash", Base64Url.encode(Crypto.sha256(nonce))).put("keyThumbprint", o.keyThumbprint);
        Json.put(body, "clientIp", o.clientIp);
        Json.put(body, "userAgent", o.userAgent);
        Json.put(body, "browser", o.browser);
        Json.put(body, "os", o.os);
        Json.put(body, "ttlSeconds", o.ttlSeconds);
        JsonNode created = http.post("/qr-pairings", body);
        String pairingId = Json.str(created, "pairingId");
        return new Created(pairingId, Json.str(created, "expiresAt"), nonce, uri(pairingId == null ? "" : pairingId, nonce, o.keyThumbprint));
    }

    /**
     * Where a pairing stands ({@code state}: waiting, scanned, confirmed, requested, approved, refused,
     * reported or expired); once scanned, who scanned it ({@code externalUsername}) and how near the phone
     * was ({@code proximity}: sameNetwork, sameCountry, warnings).
     */
    public JsonNode get(String pairingId) {
        return http.get("/qr-pairings/" + id(pairingId, "get"));
    }

    /**
     * Your own checks refused a scanned pairing (an unapproved computer, too many browsers…): the phone
     * shows {@code message} (up to 300 characters). Only a {@code scanned} or {@code confirmed} pairing can
     * be refused (409 {@code not_open} otherwise). {@code caseCode} and {@code deviceCode} ({@code ABC-123})
     * are optional.
     */
    public JsonNode refuse(String pairingId, String reason, String message, String caseCode, String deviceCode) {
        String path = "/qr-pairings/" + id(pairingId, "refuse") + "/outcome";
        if (!REFUSAL_REASONS.contains(reason)) throw new TouchQueConfigException("qrPairings.refuse(): reason must be one of " + String.join(", ", REFUSAL_REASONS) + ".");
        if (message == null || message.isBlank()) throw new TouchQueConfigException("qrPairings.refuse() needs message: what the phone shows (up to 300 characters).");
        ObjectNode body = Json.object().put("reason", reason).put("message", message);
        Json.put(body, "caseCode", caseCode);
        Json.put(body, "deviceCode", deviceCode);
        return http.post(path, body);
    }

    private static String id(String pairingId, String method) {
        if (pairingId == null || pairingId.isEmpty()) throw new TouchQueConfigException("qrPairings." + method + "() needs the pairing id.");
        return TouchQueHttp.seg(pairingId);
    }
}
