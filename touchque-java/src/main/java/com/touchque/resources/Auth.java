package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;

/** Setup secrets (the QR code the TouchQue app scans) and a user's link status. */
public final class Auth {
    private final TouchQueHttp http;

    /** Internal: use {@code tq.auth()}. */
    public Auth(TouchQueHttp http) {
        this.http = http;
    }

    /**
     * A new setup secret for a user: show {@code qrCodeDataUrl} so the TouchQue app links the
     * phone. 409 when an unscanned or used secret exists ({@link #resetSecret} issues a new one).
     */
    public JsonNode generateSecret(String externalUsername) {
        return http.post("/auth/generate-secret", Json.object().put("externalUsername", externalUsername));
    }

    /** Regenerates a user's secret. */
    public JsonNode resetSecret(String externalUsername) {
        return http.post("/auth/secret/reset", Json.object().put("externalUsername", externalUsername));
    }

    /** Checks a setup secret code. */
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
        return http.get("/users/" + TouchQueHttp.seg(externalUsername));
    }
}
