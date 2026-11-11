package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.LoginDetail;
import com.touchque.TouchqueConfigException;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Help desk: IT working on a person's account in the open.
 * <ol>
 * <li>Before your help desk acts on someone's account: {@link #open} with the person and the signed-in
 * agent. The person's phone gets a calm notice; while the session is open their "someone says they're
 * from IT" button shows this agent, and with none open it tells them to hang up (webhook
 * ASSIST_CLAIM_UNVERIFIED).</li>
 * <li>Before a sensitive action (a factor or password reset, an activation or recovery link, an unlock,
 * a new phone, removing a passkey): {@link #verify}. Show {@code challengeCode} to the agent only; they
 * read it to the person, who types it on their phone. Default deny.</li>
 * <li>Right before the action: {@link #spend} (a passed check, for that action, at most ten minutes old,
 * once). {@link #unfreeze} lifts a freeze the same way.</li>
 * </ol>
 * No phone (code {@code no_phone}, route {@code never_locked_out}): the person moves to a new phone with
 * Never Locked Out; the help desk cannot.
 */
public final class Assist {
    private final TouchqueHttp http;

    /** Internal: use {@code tq.assist()}. */
    public Assist(TouchqueHttp http) {
        this.http = http;
    }

    /** The help-desk agent: {@code name} (and {@code title}) are shown on the person's phone; {@code ref} is your id for them. */
    public record Agent(String name, String title, String ref) {
        public static Agent of(String name) {
            return new Agent(name, null, null);
        }
    }

    /** The check of {@code requestId} in a session passed on the person's phone and was not used yet. */
    public static boolean checkPassed(JsonNode session, String requestId) {
        JsonNode checks = session == null ? null : session.get("checks");
        if (checks == null || !checks.isArray()) return false;
        for (JsonNode c : checks) {
            if (requestId.equals(Json.str(c, "requestId"))) {
                JsonNode spent = c.get("spentAt");
                return "verified".equals(Json.str(c, "outcome")) && (spent == null || spent.isNull());
            }
        }
        return false;
    }

    /**
     * Starts helping a person. A session of the same agent for the same person is replaced.
     *
     * @param ttlMinutes 5-120 (null: 30)
     * @param notify     false: no notice on the person's phone
     */
    public JsonNode open(String externalUsername, Agent agent, String reason, Integer ttlMinutes, boolean notify) {
        if (externalUsername == null || externalUsername.isEmpty() || agent == null || agent.name() == null || agent.name().isEmpty()) {
            throw new TouchqueConfigException("assist.open() needs externalUsername and agent.name");
        }
        ObjectNode a = Json.object().put("name", agent.name());
        Json.put(a, "title", agent.title());
        Json.put(a, "ref", agent.ref());
        ObjectNode body = Json.object().put("externalUsername", externalUsername);
        body.set("agent", a);
        Json.put(body, "reason", reason);
        Json.put(body, "ttlMinutes", ttlMinutes);
        if (!notify) body.put("notify", false);
        return http.post("/assist", body);
    }

    /** Starts helping a person, with the notice on their phone. */
    public JsonNode open(String externalUsername, Agent agent, String reason) {
        return open(externalUsername, agent, reason, null, true);
    }

    /** The session and its checks. Poll it while a check is pending. */
    public JsonNode get(String id) {
        require("get", "the session id", id);
        return http.get(path(id, ""));
    }

    /** A person's sessions, or every open one, newest first: the {@code sessions} array. */
    public JsonNode list(String externalUsername, boolean open) {
        if ((externalUsername == null || externalUsername.isEmpty()) && !open) throw new TouchqueConfigException("assist.list() needs externalUsername or open: true");
        Map<String, Object> q = new HashMap<>();
        if (externalUsername != null && !externalUsername.isEmpty()) q.put("externalUsername", externalUsername);
        if (open) q.put("open", "true");
        return Actions.field(http.get("/assist", q), "sessions");
    }

    /**
     * Asks the person's phone to confirm {@code action} (reset_2fa, reset_password, activation_link,
     * recovery_link, unlock, new_phone, remove_passkey or your own). {@code challengeCode} is for the
     * agent only. Throws {@link com.touchque.TouchqueApiException} no_phone, assist_not_open or rate_limited.
     */
    public JsonNode verify(String id, String action, String actionText, List<LoginDetail> details) {
        require("verify", "the session id and an action", id, action);
        ObjectNode body = Json.object().put("action", action);
        Json.put(body, "actionText", actionText);
        if (details != null && !details.isEmpty()) body.set("details", LoginRequestOptions.detailsJson(details));
        return http.post(path(id, "/verify"), body);
    }

    /** Uses a passed check for its action, right before you take it; check_required (428) otherwise. */
    public JsonNode spend(String id, String requestId, String action) {
        require("spend", "the session id, requestId and action", id, requestId, action);
        return http.post(path(id, "/spend"), Json.object().put("requestId", requestId).put("action", action));
    }

    /** Lifts the person's approval freeze with a passed check for {@code unlock}. */
    public JsonNode unfreeze(String id, String requestId) {
        require("unfreeze", "the session id and requestId", id, requestId);
        return http.post(path(id, "/unfreeze"), Json.object().put("requestId", requestId));
    }

    /** Stops helping; checks still waiting on the phone expire. */
    public JsonNode end(String id, String by, String reason) {
        require("end", "the session id", id);
        ObjectNode body = Json.object();
        Json.put(body, "by", by);
        Json.put(body, "reason", reason);
        return http.post(path(id, "/end"), body);
    }

    private static String path(String id, String rest) {
        return "/assist/" + TouchqueHttp.seg(id) + rest;
    }

    private static void require(String method, String what, String... values) {
        for (String v : values) {
            if (v == null || v.isEmpty()) throw new TouchqueConfigException("assist." + method + "() needs " + what);
        }
    }
}
