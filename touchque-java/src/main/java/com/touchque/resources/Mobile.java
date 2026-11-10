package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchQueConfigException;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * TouchQue Mobile SDK, your backend's side: your own iOS/Android app is the approver of your users
 * (white-label); they never install the TouchQue app.
 * <ol>
 * <li>A user signed in to your app turns approvals on: {@link #createEnrollment} gives a one-time token;
 * your app hands it to the SDK ({@code TouchQue.enroll}).</li>
 * <li>Ask for approvals as always ({@code login().request}, {@code start}, the guards): they reach your app
 * over the SDK's encrypted connection.</li>
 * <li>Without your APNs/FCM keys in {@link #updateSettings}, TouchQue sends you a signed MOBILE_PUSH webhook
 * per request: verify it, then {@link #pushFromWebhook} gives the APNs payload / FCM data to send with
 * your own credentials.</li>
 * </ol>
 */
public final class Mobile {
    private static final Set<String> SETTING_KEYS = Set.of("iosAppIds", "androidPackages", "androidCerts", "attestation", "enrollTtlSeconds", "apns", "fcm");
    private final TouchQueHttp http;

    /** Internal: use {@code tq.mobile()}. */
    public Mobile(TouchQueHttp http) {
        this.http = http;
    }

    /**
     * A one-time enrollment token for a user you signed in ({@code enrollmentToken}, {@code tqe_…}).
     * Whoever spends it becomes the user's approver, so authenticate the user first. Throws
     * {@link com.touchque.TouchQueApiException} already_enrolled (pass {@code replace}) or account_frozen.
     */
    public JsonNode createEnrollment(String externalUsername, boolean replace, Integer ttlSeconds) {
        if (externalUsername == null || externalUsername.isEmpty()) throw new TouchQueConfigException("mobile.createEnrollment() needs the user (externalUsername)");
        ObjectNode body = Json.object().put("externalUsername", externalUsername);
        if (replace) body.put("replace", true);
        Json.put(body, "ttlSeconds", ttlSeconds);
        return http.post("/mobile/enrollments", body);
    }

    /** The devices inside your app (default: active ones), newest first: {@code {devices, nextCursor}}. {@code status}: active, revoked or all. */
    public JsonNode listDevices(String externalUsername, String status, Integer limit, String cursor) {
        Map<String, Object> q = new HashMap<>();
        if (externalUsername != null && !externalUsername.isEmpty()) q.put("externalUsername", externalUsername);
        if (status != null && !status.isEmpty()) q.put("status", status);
        q.put("limit", limit);
        if (cursor != null && !cursor.isEmpty()) q.put("cursor", cursor);
        return http.get("/mobile/devices", q);
    }

    public JsonNode getDevice(String deviceId) {
        if (deviceId == null || deviceId.isEmpty()) throw new TouchQueConfigException("mobile.getDevice() needs the device id");
        return http.get("/mobile/devices/" + TouchQueHttp.seg(deviceId)).get("device");
    }

    /** Stops a device from approving (the user has no approver until you enrol again). */
    public JsonNode removeDevice(String deviceId) {
        if (deviceId == null || deviceId.isEmpty()) throw new TouchQueConfigException("mobile.removeDevice() needs the device id");
        return http.delete("/mobile/devices/" + TouchQueHttp.seg(deviceId));
    }

    /**
     * A harmless push to the device, the way a request would reach it: {@code via} touchque (your
     * key for its platform) or webhook (MOBILE_PUSH, kind test). {@code ok}: APNs / FCM accepted it.
     */
    public JsonNode testPush(String deviceId) {
        if (deviceId == null || deviceId.isEmpty()) throw new TouchQueConfigException("mobile.testPush() needs the device id");
        return http.post("/mobile/devices/" + TouchQueHttp.seg(deviceId) + "/test-push", Json.object());
    }

    public JsonNode settings() {
        return http.get("/mobile/settings").get("settings");
    }

    /**
     * Which apps may enrol, whether they must prove themselves, and your push keys. Only the keys
     * given change: iosAppIds, androidPackages, androidCerts (package to SHA-256 of its signing
     * certificates), attestation (off | optional | required), enrollTtlSeconds, apns (keyId, teamId,
     * topic, key = the .p8 text, production: TouchQue then sends the iOS push), fcm (serviceAccount =
     * the JSON: the Android push); a null value removes a key (use a HashMap). The keys are never shown back.
     */
    public JsonNode updateSettings(Object changes) {
        JsonNode node = Json.toNode(changes);
        if (!(node instanceof ObjectNode body)) throw new TouchQueConfigException("mobile.updateSettings() takes an object of settings");
        List<String> unknown = new ArrayList<>();
        Iterator<String> names = body.fieldNames();
        while (names.hasNext()) {
            String k = names.next();
            if (!SETTING_KEYS.contains(k)) unknown.add(k);
        }
        if (!unknown.isEmpty()) throw new TouchQueConfigException("mobile.updateSettings(): unknown setting " + String.join(", ", unknown));
        return http.put("/mobile/settings", body).get("settings");
    }

    /**
     * A MOBILE_PUSH webhook, ready to send with your own APNs / FCM credentials. {@code platform} ios
     * or android; {@code pushToken} the token your app handed to the SDK (null: send by your own user
     * to device mapping); {@code kind} approval, notice or test; {@code alert} suggested English text;
     * {@code apns} the APNs payload; {@code fcmData} the FCM data map.
     */
    public record Push(String deviceId, String externalUsername, String platform, String pushToken, String requestId, String expiresAt,
                       String kind, JsonNode alert, JsonNode apns, Map<String, String> fcmData) {
        /** True once the push is past its request's expiry (don't send it any more). */
        public boolean isExpired(Instant now) {
            if (expiresAt == null) return false;
            try {
                return !Instant.parse(expiresAt).isAfter(now != null ? now : Instant.now());
            } catch (DateTimeParseException e) {
                return false;
            }
        }
    }

    /** The push to send for a verified MOBILE_PUSH webhook, or null for any other event. No secret, no details, no number in it. */
    public static Push pushFromWebhook(JsonNode event) {
        if (event == null || !"MOBILE_PUSH".equals(Json.str(event, "event"))) return null;
        JsonNode data = event.get("data");
        JsonNode t = data == null ? null : data.get("touchque");
        String touchque = t == null || t.isNull() ? "{}" : t.isTextual() ? t.textValue() : Json.write(t);
        ObjectNode aps = Json.object().put("sound", "default").put("interruption-level", "time-sensitive");
        ObjectNode alert = null;
        JsonNode a = event.get("alert");
        if (a != null && a.isObject()) {
            alert = Json.object().put("title", Json.str(a, "title") != null ? Json.str(a, "title") : "").put("body", Json.str(a, "body") != null ? Json.str(a, "body") : "");
            aps.set("alert", alert.deepCopy());
        }
        ObjectNode apns = Json.object();
        apns.set("aps", aps);
        apns.put("touchque", touchque);
        String kind = Json.str(event, "kind");
        return new Push(Json.str(event, "deviceId"), Json.str(event, "externalUsername"),
                "android".equals(Json.str(event, "platform")) ? "android" : "ios", Json.str(event, "pushToken"), Json.str(event, "requestId"),
                Json.str(event, "expiresAt"), "notice".equals(kind) || "test".equals(kind) ? kind : "approval", alert, apns, Map.of("touchque", touchque));
    }
}
