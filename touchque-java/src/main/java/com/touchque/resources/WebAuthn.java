package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;
import java.util.Map;

/**
 * WebAuthn / FIDO2 (passkeys), the backend half. The ceremony runs in the browser
 * ({@code @touchque/web}); your backend relays its JSON through these methods (or the relay does
 * it for you).
 */
public final class WebAuthn {
    private final TouchQueHttp http;

    /** Internal: use {@code tq.webauthn()}. */
    public WebAuthn(TouchQueHttp http) {
        this.http = http;
    }

    /**
     * Step 1 of registration: options for {@code navigator.credentials.create()}. {@code discoverable}
     * registers a resident credential (the shape a passwordless sign-in uses). A user with a linked
     * phone needs {@code approvalRequestId}: a PASSKEY_ENROLL request they approved on the phone, at
     * most 10 minutes old, used once (403 enrollment_approval_required otherwise).
     */
    public JsonNode registerOptions(String externalUsername, boolean discoverable, String approvalRequestId) {
        ObjectNode body = Json.object().put("externalUsername", externalUsername);
        if (discoverable) body.put("discoverable", true);
        Json.put(body, "approvalRequestId", approvalRequestId);
        return http.post("/webauthn/register/options", body);
    }

    /** Step 2 of registration: verifies the browser's answer ({@code verified}, {@code credentialId}). */
    public JsonNode registerVerify(String externalUsername, JsonNode response, String label) {
        ObjectNode body = Json.object().put("externalUsername", externalUsername);
        body.set("response", response.deepCopy());
        if (label != null) body.put("label", label);
        return http.post("/webauthn/register/verify", body);
    }

    /** Second factor, step 1: options for {@code navigator.credentials.get()}, scoped to a pending request. */
    public JsonNode authenticateOptions(String requestId) {
        return http.post("/webauthn/login/options", Json.object().put("requestId", requestId));
    }

    /** Second factor, step 2: verifies the assertion and approves the request. {@code externalUsername}: trust this, never a name the browser sent. */
    public JsonNode authenticateVerify(String requestId, JsonNode response) {
        ObjectNode body = Json.object().put("requestId", requestId);
        body.set("response", response.deepCopy());
        return http.post("/webauthn/login/verify", body);
    }

    /**
     * Whether passkey sign-in (passwordlessLoginEnabled) is on for your workspace. Ask before your
     * sign-in page shows its passkey button and passkey autofill: when it is off,
     * {@link #primaryOptions} answers 403 passwordless_login_disabled. The answer has
     * {@code enabled} and {@code userVerification} ("required" or "preferred", null when off).
     */
    public JsonNode primaryAvailability() {
        JsonNode res = http.get("/webauthn/authenticate/primary/availability");
        boolean enabled = res != null && res.path("enabled").isBoolean() && res.path("enabled").asBoolean();
        String uv = res != null && res.path("userVerification").isTextual() ? res.path("userVerification").asText() : null;
        ObjectNode out = Json.object().put("enabled", enabled);
        if (enabled && ("required".equals(uv) || "preferred".equals(uv))) out.put("userVerification", uv);
        else out.putNull("userVerification");
        return out;
    }

    /**
     * Passwordless sign-in, step 1 (needs passwordlessLoginEnabled). 404 no_passkey_registered:
     * fall back to the password. Without a user (null) the options accept any passkey of your site
     * (passkey autofill). The answer has {@code attemptId} and {@code options}.
     */
    public JsonNode primaryOptions(String externalUsername) {
        return http.post("/webauthn/authenticate/primary/options", Json.put(Json.object(), "externalUsername", externalUsername));
    }

    /** Passwordless sign-in, step 2. On success {@code requestId} is a CONFIRMED request; with {@code requiresStepUp} start the normal push flow instead. */
    public JsonNode primaryVerify(String attemptId, JsonNode response) {
        ObjectNode body = Json.object().put("attemptId", attemptId);
        body.set("response", response.deepCopy());
        return http.post("/webauthn/authenticate/primary/verify", body);
    }

    /** A user's passkeys (metadata only, no key material): the {@code credentials} array. */
    public JsonNode listCredentials(String externalUsername) {
        JsonNode res = http.get("/webauthn/credentials", Map.of("externalUsername", externalUsername));
        JsonNode list = res.get("credentials");
        return list != null && list.isArray() ? list : Json.array();
    }

    /**
     * Removes a passkey. Pass {@code externalUsername} to scope it to that user (recommended:
     * without it any credential your API key can reach is deletable).
     */
    public boolean deleteCredential(String credentialRecordId, String externalUsername) {
        String path = "/webauthn/credentials/" + TouchQueHttp.seg(credentialRecordId);
        if (externalUsername != null) path += "?externalUsername=" + TouchQueHttp.seg(externalUsername);
        return Json.bool(http.delete(path), "deleted");
    }
}
