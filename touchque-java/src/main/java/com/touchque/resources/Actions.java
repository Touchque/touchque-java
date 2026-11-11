package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueConfigException;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Touchque Actions: your own code at points of the approval pipeline (before the push is sent, the
 * silent sign-in decision, an AI agent's request, after an approval, fraud reports, device and
 * recovery events). Touchque runs it in a sandbox; this resource deploys, tests, replays and observes it.
 *
 * <pre>{@code
 * tq.actions().deploy("night-alert", new Actions.DeployOptions()
 *     .trigger("approval.decided")
 *     .template(Actions.TemplateRef.of("alert", Map.of("channel", "slack", "when", Map.of("countries", List.of("TR"))))));
 * }</pre>
 *
 * Action code itself is JavaScript ({@code exports.onExecute = async (event, api) => {...}}),
 * whatever language your server is written in. Triggers are plain names (login.request,
 * risk.check, agent.approval, approval.decided…; see ACTIONS.md).
 */
public final class Actions {
    private static final Pattern SLUG = Pattern.compile("^[a-z0-9][a-z0-9-]{1,62}$");
    private static final Pattern TEMPLATE = Pattern.compile("^[a-z_]{1,64}$");

    private final TouchqueHttp http;
    private final Secrets secrets;

    /** Internal: use {@code tq.actions()}. */
    public Actions(TouchqueHttp http) {
        this.http = http;
        this.secrets = new Secrets(http);
    }

    /** Secrets your Actions read ({@code event.secrets.NAME}) or notify with. */
    public Secrets secrets() {
        return secrets;
    }

    /** A no-code template and its parameters (any object: a Map, a record, a JsonNode). */
    public record TemplateRef(String id, Object params) {
        public static TemplateRef of(String id, Object params) {
            return new TemplateRef(id, params);
        }

        ObjectNode toJson() {
            ObjectNode o = Json.object().put("id", id);
            if (params != null) o.set("params", Json.toNode(params));
            return o;
        }
    }

    /** What {@link #deploy} sends. Trigger is required for a new Action and cannot change later; code or template is required. */
    public static final class DeployOptions {
        String trigger;
        String name;
        String code;
        TemplateRef template;
        List<String> secrets;
        List<String> allowedHosts;
        List<String> capabilities;
        String onFailure;
        Integer order;
        Boolean enabled;
        Boolean activate;

        public DeployOptions trigger(String v) {
            this.trigger = v;
            return this;
        }

        public DeployOptions name(String v) {
            this.name = v;
            return this;
        }

        public DeployOptions code(String v) {
            this.code = v;
            return this;
        }

        public DeployOptions template(TemplateRef v) {
            this.template = v;
            return this;
        }

        public DeployOptions secrets(List<String> v) {
            this.secrets = v;
            return this;
        }

        public DeployOptions allowedHosts(List<String> v) {
            this.allowedHosts = v;
            return this;
        }

        /** Loosening powers (skip_number_match, override_block, allow_silent); each needs an admin's phone approval. */
        public DeployOptions capabilities(List<String> v) {
            this.capabilities = v;
            return this;
        }

        /** Pre triggers: {@code continue} (default, never blocks), {@code step_up} or {@code deny}. */
        public DeployOptions onFailure(String v) {
            this.onFailure = v;
            return this;
        }

        public DeployOptions order(Integer v) {
            this.order = v;
            return this;
        }

        public DeployOptions enabled(Boolean v) {
            this.enabled = v;
            return this;
        }

        /** False saves the version without making it live. */
        public DeployOptions activate(Boolean v) {
            this.activate = v;
            return this;
        }
    }

    /**
     * Code to test or replay: code or template (with trigger), or slug for a deployed Action.
     * {@code eventId}, {@code event}, {@code network} are for {@link #test}; {@code replaces},
     * {@code onFailure}, {@code limit}, {@code since} for {@link #dryRun}.
     */
    public static final class Draft {
        String trigger;
        String code;
        TemplateRef template;
        String slug;
        List<String> secrets;
        List<String> allowedHosts;
        List<String> capabilities;
        String eventId;
        Object event;
        Boolean network;
        String replaces;
        String onFailure;
        Integer limit;
        Instant since;

        public Draft trigger(String v) {
            this.trigger = v;
            return this;
        }

        public Draft code(String v) {
            this.code = v;
            return this;
        }

        public Draft template(TemplateRef v) {
            this.template = v;
            return this;
        }

        public Draft slug(String v) {
            this.slug = v;
            return this;
        }

        public Draft secrets(List<String> v) {
            this.secrets = v;
            return this;
        }

        public Draft allowedHosts(List<String> v) {
            this.allowedHosts = v;
            return this;
        }

        public Draft capabilities(List<String> v) {
            this.capabilities = v;
            return this;
        }

        /** test: a recorded event ({@link #events}). */
        public Draft eventId(String v) {
            this.eventId = v;
            return this;
        }

        /** test: your own event, merged over the trigger's sample. */
        public Draft event(Object v) {
            this.event = v;
            return this;
        }

        /** test: false turns {@code api.fetch} off. */
        public Draft network(Boolean v) {
            this.network = v;
            return this;
        }

        /** dryRun: the deployed Action this draft would replace. */
        public Draft replaces(String v) {
            this.replaces = v;
            return this;
        }

        public Draft onFailure(String v) {
            this.onFailure = v;
            return this;
        }

        /** dryRun: how many recent events (1-1000; the API's default is 500). */
        public Draft limit(Integer v) {
            this.limit = v;
            return this;
        }

        public Draft since(Instant v) {
            this.since = v;
            return this;
        }
    }

    /**
     * Creates the Action or adds a version and makes it live (idempotent: the same code and settings
     * change nothing). A version asking for a loosening capability (skip_number_match,
     * override_block, allow_silent) waits for an admin's phone approval: then {@code deployed} is
     * false and {@code approval.required} true.
     */
    public JsonNode deploy(String slug, DeployOptions o) {
        String path = slugPath(slug);
        if ((o.code == null || o.code.isEmpty()) && o.template == null) throw new TouchqueConfigException("actions.deploy() needs code or template");
        ObjectNode body = Json.object();
        Json.put(body, "trigger", o.trigger);
        Json.put(body, "code", o.code);
        if (o.template != null) body.set("template", o.template.toJson());
        Json.put(body, "name", o.name);
        putList(body, "secrets", o.secrets);
        putList(body, "allowedHosts", o.allowedHosts);
        putList(body, "capabilities", o.capabilities);
        Json.put(body, "onFailure", o.onFailure);
        Json.put(body, "order", o.order);
        Json.put(body, "enabled", o.enabled);
        Json.put(body, "activate", o.activate);
        return http.put(path, body);
    }

    /** Every Action: the {@code actions} array. */
    public JsonNode list() {
        return field(http.get("/actions"), "actions");
    }

    /** The Action, the active version's code and its versions. */
    public JsonNode get(String slug) {
        return http.get(slugPath(slug));
    }

    /** One version, with its code. */
    public JsonNode version(String slug, int number) {
        JsonNode res = http.get(slugPath(slug) + "/versions/" + number);
        return res.has("version") ? res.get("version") : res;
    }

    /** Rename, turn on or off, reorder, change onFailure (null fields stay as they are). */
    public JsonNode update(String slug, String name, Boolean enabled, Integer order, String onFailure) {
        ObjectNode body = Json.object();
        Json.put(body, "name", name);
        Json.put(body, "enabled", enabled);
        Json.put(body, "order", order);
        Json.put(body, "onFailure", onFailure);
        JsonNode res = http.patch(slugPath(slug), body);
        return res.has("action") ? res.get("action") : res;
    }

    public void delete(String slug) {
        http.delete(slugPath(slug));
    }

    /** Back to {@code version}, or (null) to the newest runnable version before the active one. Takes effect at once. */
    public JsonNode rollback(String slug, Integer version) {
        return http.post(slugPath(slug) + "/rollback", Json.put(Json.object(), "version", version));
    }

    /** Runs a draft (or the deployed Action {@code slug}) once on a recorded event, your own event or the trigger's sample. Sends nothing. */
    public JsonNode test(Draft d) {
        ObjectNode body = draftJson(d);
        Json.put(body, "eventId", d.eventId);
        if (d.event != null) body.set("event", Json.toNode(d.event));
        Json.put(body, "network", d.network);
        return http.post("/actions/test", body);
    }

    /**
     * Replays a draft against recent real decisions: how many it would have changed
     * ({@code changed}, {@code transitions} such as {@code push→number_match: 12}), notifications it
     * would have sent, errors and timing.
     */
    public JsonNode dryRun(Draft d) {
        ObjectNode body = draftJson(d);
        Json.put(body, "replaces", d.replaces);
        Json.put(body, "onFailure", d.onFailure);
        Json.put(body, "limit", d.limit);
        if (d.since != null) body.put("since", d.since.toString());
        return http.post("/actions/dry-run", body);
    }

    /** Recorded events (newest first, kept 30 days); use an id with {@link #test}. */
    public JsonNode events(String trigger, Integer limit) {
        Map<String, Object> q = new HashMap<>();
        q.put("trigger", trigger);
        q.put("limit", limit);
        return field(http.get("/actions/events", q), "events");
    }

    /** Live runs: decision, notifications, console output, errors. */
    public JsonNode logs(String slug, Integer limit, Instant before) {
        Map<String, Object> q = new HashMap<>();
        q.put("limit", limit);
        q.put("before", before == null ? null : before.toString());
        return field(http.get(slugPath(slug) + "/logs", q), "logs");
    }

    /** {@code window}: 1h, 24h (default), 7d or 30d. */
    public JsonNode metrics(String slug, String window) {
        Map<String, Object> q = new HashMap<>();
        q.put("window", window);
        return http.get(slugPath(slug) + "/metrics", q);
    }

    /** Every trigger with its decisions, capabilities, notification types and a sample event. */
    public JsonNode triggers() {
        return http.get("/actions/triggers");
    }

    /** The no-code templates: the {@code templates} array. */
    public JsonNode templates() {
        return field(http.get("/actions/templates"), "templates");
    }

    /** A template as plain code (to read, or to start a code Action from). */
    public JsonNode renderTemplate(String id, String trigger, Object params) {
        if (id == null || !TEMPLATE.matcher(id).matches()) throw new TouchqueConfigException("Unknown template id");
        ObjectNode body = Json.object().put("trigger", trigger);
        body.set("params", params == null ? Json.object() : Json.toNode(params));
        return http.post("/actions/templates/" + id + "/render", body);
    }

    private static String slugPath(String slug) {
        if (slug == null || !SLUG.matcher(slug).matches()) {
            throw new TouchqueConfigException("An Action slug is 2-63 lowercase letters, digits or - (e.g. \"night-alert\")");
        }
        return "/actions/" + slug;
    }

    private static ObjectNode draftJson(Draft d) {
        ObjectNode body = Json.object();
        Json.put(body, "trigger", d.trigger);
        Json.put(body, "slug", d.slug);
        Json.put(body, "code", d.code);
        if (d.template != null) body.set("template", d.template.toJson());
        putList(body, "secrets", d.secrets);
        putList(body, "allowedHosts", d.allowedHosts);
        putList(body, "capabilities", d.capabilities);
        return body;
    }

    static void putList(ObjectNode body, String key, List<String> values) {
        if (values != null) body.set(key, Json.toNode(values));
    }

    static JsonNode field(JsonNode res, String key) {
        JsonNode v = res == null ? null : res.get(key);
        return v != null && v.isArray() ? v : Json.array();
    }

    /** Secrets your Actions read or notify with. A value is encrypted and never readable again. */
    public static final class Secrets {
        private static final Pattern NAME = Pattern.compile("^[A-Z][A-Z0-9_]{0,63}$");
        private final TouchqueHttp http;

        Secrets(TouchqueHttp http) {
            this.http = http;
        }

        public JsonNode set(String name, String value) {
            if (value == null || value.isEmpty()) throw new TouchqueConfigException("A secret value is a non-empty string");
            JsonNode res = http.put(path(name), Json.object().put("value", value));
            return res.has("secret") ? res.get("secret") : res;
        }

        /** Names only: the {@code secrets} array. */
        public JsonNode list() {
            return field(http.get("/actions/secrets"), "secrets");
        }

        public void delete(String name) {
            http.delete(path(name));
        }

        private static String path(String name) {
            if (name == null || !NAME.matcher(name).matches()) {
                throw new TouchqueConfigException("A secret name is capital letters, digits or _ (e.g. SLACK_WEBHOOK_URL)");
            }
            return "/actions/secrets/" + name;
        }
    }
}
