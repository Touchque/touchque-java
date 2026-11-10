package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchQueConfigException;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;
import java.util.ArrayList;
import java.util.List;

/**
 * Device risk (a paid add-on, off until your workspace turns it on): a visitor ID for every browser on
 * your sign-up, password-reset, sign-in or approval page. The page identifies with {@code @touchque/web}
 * ({@code deviceRisk.identify({ siteKey, purpose })} gives {@code { visitorId, requestId, confidence }})
 * and sends you the requestId. Never trust the page's copy: read the identification here
 * ({@link #getEvent}) or check it for an account ({@link #check}). TouchQue keeps keyed hashes only, with
 * a key of your workspace alone, and its risk engine decides.
 *
 * <p>Every signal only ever asks for more: {@code stepUp} means an extra check on this page (an emailed
 * code, a passkey, a number-matched approval), never a refusal. For sign-ins, pass the requestId as
 * {@code deviceRiskRequestId} in {@link LoginRequestOptions} and {@link Risk.CheckOptions} instead.
 * Collect it only on these pages and name it in your privacy notice.
 *
 * <p>With the script tag (device.js), the form arrives with {@code touchque_request_id}:
 * {@code tq.deviceRisk().check(CheckOptions.ofRequest(request.getParameter("touchque_request_id")).externalUsername(email))}.
 * Pass it as it came. Missing, empty, made up or expired, it is still a verdict ({@code report} missing,
 * unknown, expired; the signal device_identification_missing), never an exception: a page without the tag,
 * or with it blocked, only gets the visitor a step-up.
 */
public final class DeviceRisk {
    /** The pages a device report may come from. */
    public static final List<String> EVENTS = List.of("sign_in", "sign_up", "password_reset", "approval");

    /** What the page had sent: ok, replayed, or no usable identification. */
    public static final List<String> REPORTS = List.of("ok", "replayed", "missing", "unknown", "expired", "invalid");
    private static final java.util.regex.Pattern REQUEST_ID = java.util.regex.Pattern.compile("^dre_[A-Za-z0-9_-]{22}$");
    private final TouchQueHttp http;

    /** Internal: use {@code tq.deviceRisk()}. */
    public DeviceRisk(TouchQueHttp http) {
        this.http = http;
    }

    /** One page's identification, for an account: {@link #ofRequest} (deviceRisk.identify) or {@link #ofReport} (deviceRisk.collect). */
    public static final class CheckOptions {
        private final String requestId;
        private final String deviceRisk;
        private String event = "sign_in";
        private String externalUsername;
        private String clientIp;

        private CheckOptions(String requestId, String deviceRisk) {
            this.requestId = requestId;
            this.deviceRisk = deviceRisk;
        }

        /** @param requestId the {@code touchque_request_id} form field (the script tag) or {@code deviceRisk.identify()}'s requestId, as it came: null or empty is answered {@code missing} */
        public static CheckOptions ofRequest(String requestId) {
            return new CheckOptions(requestId, null);
        }

        /** @param deviceRisk the page's report from {@code deviceRisk.collect()}, relayed untouched */
        public static CheckOptions ofReport(String deviceRisk) {
            return new CheckOptions(null, deviceRisk);
        }

        /** {@code sign_in} (default), {@code sign_up}, {@code password_reset} or {@code approval}. */
        public CheckOptions event(String v) {
            this.event = v;
            return this;
        }

        /** The account the page is for, when there is one. One account per identification. */
        public CheckOptions externalUsername(String v) {
            this.externalUsername = v;
            return this;
        }

        /** The end user's address; default: where the browser identified from. */
        public CheckOptions clientIp(String v) {
            this.clientIp = v;
            return this;
        }
    }

    /**
     * A signal. {@code code}: device_tampered, device_virtual, device_geo_mismatch,
     * device_many_accounts, device_signup_burst, device_id_resets, device_many_countries,
     * device_wrong_site, device_report_replayed, device_private_window (context only),
     * device_step_up_by_admin, device_identification_missing (no identification, or one that does not
     * verify). {@code strength}: number_match, passkey or none.
     */
    public record Signal(String code, String text, String strength, boolean enforced, JsonNode evidence) {
    }

    /**
     * The answer. {@code report}: ok; replayed (another account, or sent twice); or no usable identification,
     * which raises device_identification_missing: missing (none or empty), unknown (made up, or another
     * workspace's), expired (over 15 minutes old), invalid. {@code visitorId} ({@code tqv_…}) is this
     * browser in your workspace only. {@code stepUp}: ask for more on this page, never a reason to refuse.
     * {@code mode}: enforce when at least one raised signal is enforced, else shadow. {@code caseCode} opens
     * the decision record ("Why?"). {@code network}: the address as the risk engine saw it (never
     * coordinates; type isp, hosting, tor or unknown). {@code velocity}: the visitor's counts. {@code bot}: one
     * answer to "a bot?" (result detected, suspected or not_detected, and reasons). {@code engine}: the engine's
     * state for this check; "unavailable" when the risk engine could not be reached and the verdict is a safe default
     * (null when the answer carries none).
     */
    public record CheckResult(String report, String requestId, String visitorId, Double confidence, JsonNode visitor, JsonNode counts,
            JsonNode network, JsonNode velocity, JsonNode bot,
            List<Signal> signals, boolean stepUp, boolean wouldStepUp, String requires, String mode, String caseCode, String engine) {
        /** The answer without {@code engine} (null), as before it was added. */
        public CheckResult(String report, String requestId, String visitorId, Double confidence, JsonNode visitor, JsonNode counts,
                JsonNode network, JsonNode velocity, JsonNode bot,
                List<Signal> signals, boolean stepUp, boolean wouldStepUp, String requires, String mode, String caseCode) {
            this(report, requestId, visitorId, confidence, visitor, counts, network, velocity, bot, signals, stepUp, wouldStepUp, requires, mode, caseCode, null);
        }
    }

    /** The page's {@code touchque_request_id} form field as it came, for a sign-in: see {@link #check(CheckOptions)}. */
    public CheckResult check(String requestId) {
        return check(CheckOptions.ofRequest(requestId));
    }

    /**
     * Checks the page's identification for an account: binds it (one account, 15 minutes) and asks the risk
     * engine. Pass the form field as it came: null, empty or made up is still a verdict ({@code report}
     * missing, unknown), never an exception. 409 {@code device_risk_off} while off.
     */
    public CheckResult check(CheckOptions o) {
        if (o == null) o = CheckOptions.ofRequest(null);
        if (!EVENTS.contains(o.event)) throw new TouchQueConfigException("deviceRisk.check(): event must be one of " + String.join(", ", EVENTS));
        ObjectNode body = Json.object();
        if (o.requestId != null && !o.requestId.isEmpty()) body.put("requestId", o.requestId.length() > 64 ? o.requestId.substring(0, 64) : o.requestId);
        else if (o.deviceRisk != null && !o.deviceRisk.isEmpty()) body.put("deviceRisk", o.deviceRisk);
        body.put("event", o.event);
        Json.put(body, "externalUsername", o.externalUsername);
        Json.put(body, "clientIp", o.clientIp);
        return parseCheck(http.post("/device-risk/check", body));
    }

    /**
     * {@link #searchEvents}' filters, each one only when set. {@code from}/{@code to}: YYYY-MM-DD or ISO times
     * (7 days by default, at most 90, within your retention); {@code ip}: an address or a CIDR range, never
     * returned; {@code cursor}: the previous page's {@code nextCursor}, as it came; {@code limit}: 1 to 100.
     */
    public static final class SearchOptions {
        private final java.util.Map<String, String> params = new java.util.LinkedHashMap<>();

        private SearchOptions put(String key, String value) {
            if (value != null && !value.isEmpty()) params.put(key, value);
            return this;
        }

        public SearchOptions from(String v) { return put("from", v); }
        public SearchOptions to(String v) { return put("to", v); }
        public SearchOptions signal(String v) { return put("signal", v); }
        public SearchOptions stepUp(boolean v) { return put("stepUp", v ? "true" : "false"); }
        public SearchOptions kind(String v) { return put("kind", v); }
        public SearchOptions origin(String v) { return put("origin", v); }
        public SearchOptions ip(String v) { return put("ip", v); }
        public SearchOptions account(String v) { return put("account", v); }
        public SearchOptions visitorId(String v) { return put("visitorId", v); }
        public SearchOptions requestId(String v) { return put("requestId", v); }
        public SearchOptions cursor(String v) { return put("cursor", v); }

        public SearchOptions limit(int v) {
            if (v < 1 || v > 100) throw new TouchQueConfigException("deviceRisk.searchEvents() limit must be 1 to 100");
            return put("limit", Integer.toString(v));
        }
    }

    /** One page: pass {@code nextCursor} back as {@code cursor} until it is null. No event carries an address. */
    public record SearchResult(List<JsonNode> events, String nextCursor, String from, String to) {}

    /**
     * Your workspace's identifications, newest first, one page at a time ({@code GET /device-risk/events}).
     * Do not page by moving the dates. A search that would read too much is a 422 {@code search_too_broad}:
     * narrow the range or add a filter.
     */
    public SearchResult searchEvents(SearchOptions options) {
        JsonNode res = http.get("/device-risk/events", options == null ? java.util.Map.of() : options.params);
        List<JsonNode> events = new ArrayList<>();
        if (res != null && res.path("events").isArray()) res.path("events").forEach(events::add);
        String next = res != null && res.path("nextCursor").isTextual() && !res.path("nextCursor").asText().isEmpty() ? res.path("nextCursor").asText() : null;
        return new SearchResult(events, next, res == null ? "" : res.path("from").asText(""), res == null ? "" : res.path("to").asText(""));
    }

    /** The trusted identification behind a requestId: the visitor, how sure, what the page showed, the engine's verdict. Read-only. */
    public JsonNode getEvent(String requestId) {
        if (requestId == null || !REQUEST_ID.matcher(requestId).matches()) throw new TouchQueConfigException("deviceRisk.getEvent() needs a requestId (dre_…)");
        return http.get("/device-risk/events/" + requestId, java.util.Map.of());
    }

    /** Reads an answer, failing toward asking: {@code stepUp} is true unless it says exactly false; junk signals are dropped. */
    public static CheckResult parseCheck(JsonNode raw) {
        JsonNode body = raw instanceof ObjectNode ? raw : Json.object();
        List<Signal> signals = new ArrayList<>();
        JsonNode arr = body.get("signals");
        if (arr != null && arr.isArray()) {
            for (JsonNode s : arr) {
                String code = Json.str(s, "code");
                if (code == null) continue;
                String strength = Json.str(s, "strength");
                JsonNode evidence = s.get("evidence");
                JsonNode enforced = s.get("enforced");
                signals.add(new Signal(code, Json.str(s, "text") != null ? Json.str(s, "text") : "",
                        "passkey".equals(strength) || "none".equals(strength) ? strength : "number_match",
                        enforced != null && enforced.isBoolean() && enforced.booleanValue(),
                        evidence != null && evidence.isObject() ? evidence : null));
            }
        }
        String report = Json.str(body, "report");
        String requires = Json.str(body, "requires");
        JsonNode stepUp = body.get("stepUp");
        JsonNode would = body.get("wouldStepUp");
        JsonNode visitor = body.get("visitor");
        JsonNode counts = body.get("counts");
        JsonNode confidence = body.get("confidence");
        return new CheckResult(
                report != null && REPORTS.contains(report) ? report : "invalid",
                Json.str(body, "requestId"), Json.str(body, "visitorId"),
                confidence != null && confidence.isNumber() ? confidence.doubleValue() : null,
                visitor != null && visitor.isObject() ? visitor : null,
                counts != null && counts.isObject() ? counts : null,
                object(body.get("network")), object(body.get("velocity")), object(body.get("bot")),
                signals,
                !(stepUp != null && stepUp.isBoolean() && !stepUp.booleanValue()),
                would != null && would.isBoolean() && would.booleanValue(),
                "number_match".equals(requires) || "passkey".equals(requires) ? requires : "none",
                "enforce".equals(Json.str(body, "mode")) ? "enforce" : "shadow",
                Json.str(body, "caseCode"),
                Json.str(body, "engine"));
    }

    private static JsonNode object(JsonNode n) {
        return n != null && n.isObject() ? n : null;
    }
}
