package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;
import java.util.List;

/**
 * Action types (LOGIN, SEND_MONEY…): what a user is asked to approve. Define them from code at
 * start-up instead of clicking them into the dashboard.
 */
public final class ActionTypes {
    /** The Second Thought questions an action type can ask (at most two). */
    public static final List<String> SECOND_THOUGHT_QUESTIONS = List.of(
            "someone_guiding", "safe_account", "remote_access", "asked_for_code", "support_call",
            "met_online", "promised_return", "know_recipient", "sim_in_hand");

    private final TouchQueHttp http;

    /** Internal: use {@code tq.actionTypes()}. */
    public ActionTypes(TouchQueHttp http) {
        this.http = http;
    }

    /** Second Thought questions of an action type; {@code locale} tr or en. */
    public record SecondThought(List<String> questions, String locale) {
    }

    /**
     * Creates the action type, or updates its name, description, critical flag and Second Thought
     * questions. Safe on every start-up: it never re-enables a type an admin disabled.
     * {@code secondThought}: at most two of {@link #SECOND_THOUGHT_QUESTIONS}, asked on the phone
     * before Approve (a risky answer makes the approval provisional); an empty list turns them off,
     * null keeps what the dashboard has. Null name: the type.
     */
    public JsonNode define(String type, String name, String description, Boolean critical, SecondThought secondThought) {
        ObjectNode body = Json.object().put("type", type).put("name", name != null ? name : type);
        if (description != null) body.put("description", description);
        Json.put(body, "critical", critical);
        if (secondThought != null) {
            ObjectNode st = Json.object();
            ArrayNode q = Json.array();
            if (secondThought.questions() != null) secondThought.questions().forEach(q::add);
            st.set("questions", q);
            Json.put(st, "locale", secondThought.locale());
            body.set("secondThought", st);
        }
        return http.post("/action-types", body);
    }

    /** Creates or updates the action type with its name. */
    public JsonNode define(String type, String name, boolean critical) {
        return define(type, name, null, critical, null);
    }

    /** Every action type: a JSON array. */
    public JsonNode list() {
        return http.get("/action-types");
    }
}
