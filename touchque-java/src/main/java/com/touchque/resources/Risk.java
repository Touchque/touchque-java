package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.RiskReason;
import com.touchque.TouchqueConfigException;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Silent sign-ins: ask Touchque's risk engine whether a sign-in needs the phone at all, and manage
 * the browsers it knows for a user. A browser becomes known when the user approves a request that
 * carried the browser's device-bound key proof; later {@link #check} with a fresh proof from the same
 * browser answers {@code prompt = false} when nothing about the sign-in is new.
 */
public final class Risk {
    private static final Set<String> ASSURANCE_LEVELS = Set.of("high", "normal", "low");
    private final TouchqueHttp http;

    /** Internal: use {@code tq.risk()}. */
    public Risk(TouchqueHttp http) {
        this.http = http;
    }

    /** What to check. */
    public static final class CheckOptions {
        private final String externalUsername;
        private String type;
        private String clientIp;
        private String userAgent;
        private String browserProof;
        private String clientSignals;
        private String deviceRisk;
        private String deviceRiskRequestId;
        private Integer maxAgeSeconds;
        private Map<String, Object> context;

        /** @param externalUsername the user in YOUR system */
        public CheckOptions(String externalUsername) {
            this.externalUsername = externalUsername;
        }

        /** The action the user is about to do (default LOGIN); a critical action always asks. */
        public CheckOptions type(String v) {
            this.type = v;
            return this;
        }

        /** The end user's IP, compared with the networks of earlier approved sign-ins. */
        public CheckOptions clientIp(String v) {
            this.clientIp = v;
            return this;
        }

        public CheckOptions userAgent(String v) {
            this.userAgent = v;
            return this;
        }

        /** The browser's device-bound key proof ({@code X-Touchque-Browser}), passed through untouched. */
        public CheckOptions browserProof(String v) {
            this.browserProof = v;
            return this;
        }

        /** The end user's page check from {@code @touchque/web}: software driving the browser is never silent. */
        public CheckOptions clientSignals(String v) {
            this.clientSignals = v;
            return this;
        }

        /** The page's device report from {@code @touchque/web} ({@code deviceRisk.collect}): a device signal is never silent. */
        public CheckOptions deviceRisk(String v) {
            this.deviceRisk = v;
            return this;
        }

        /** The page's identification ({@code deviceRisk.identify()}), preferred over deviceRisk; for this account only. */
        public CheckOptions deviceRiskRequestId(String v) {
            this.deviceRiskRequestId = v;
            return this;
        }

        /** Your own limit on how long ago the last phone approval in this browser may be; 0 = always ask. Touchque never goes beyond 7 days. */
        public CheckOptions maxAgeSeconds(Integer v) {
            this.maxAgeSeconds = v;
            return this;
        }

        /** For your Touchque Actions only ({@code event.context}). */
        public CheckOptions context(Map<String, Object> v) {
            this.context = v;
            return this;
        }
    }

    /**
     * The answer: {@code prompt} is false ONLY when Touchque said exactly {@code prompt: false}.
     * Reasons when silent: known_browser, recent_approval, same_phone, familiar_network,
     * no_risk_signal; when asked: no_browser_key, new_browser, approval_too_old, critical_action,
     * risk_signal, silent_mode_shadow… {@code assurance}: high, normal or low. {@code silentMode}
     * {@code shadow}: silent sign-ins are only measured, so prompt is always true.
     */
    public record CheckResult(boolean prompt, List<RiskReason> reasons, String assurance, String silentMode, String caseCode) {
    }

    /** Should this sign-in ask the phone? Skip the push only when {@code prompt} is false; on any error, ask as usual. */
    public CheckResult check(CheckOptions o) {
        if (o.externalUsername == null || o.externalUsername.isEmpty()) throw new TouchqueConfigException("risk.check() needs the user (externalUsername)");
        if (o.maxAgeSeconds != null && o.maxAgeSeconds < 0) throw new TouchqueConfigException("risk.check(): maxAgeSeconds must be >= 0 (0 = always ask)");
        ObjectNode body = Json.object().put("externalUsername", o.externalUsername);
        Json.put(body, "type", o.type);
        Json.put(body, "clientIp", o.clientIp);
        Json.put(body, "userAgent", o.userAgent);
        Json.put(body, "browserProof", o.browserProof);
        Json.put(body, "clientSignals", o.clientSignals);
        Json.put(body, "deviceRisk", o.deviceRisk);
        Json.put(body, "deviceRiskRequestId", o.deviceRiskRequestId);
        Json.put(body, "maxAgeSeconds", o.maxAgeSeconds);
        if (o.context != null && !o.context.isEmpty()) body.set("context", Json.toNode(o.context));
        return parseCheck(http.post("/risk/check", body));
    }

    /**
     * Reads a {@code POST /risk/check} answer, failing closed: {@code prompt} is false ONLY when the
     * answer says exactly {@code prompt: false} (a boolean). Malformed reasons become empty, and an
     * unknown or missing assurance is {@code normal}.
     */
    public static CheckResult parseCheck(JsonNode raw) {
        JsonNode body = raw instanceof ObjectNode ? raw : Json.object();
        JsonNode p = body.get("prompt");
        boolean prompt = !(p != null && p.isBoolean() && !p.booleanValue());
        List<RiskReason> reasons = new ArrayList<>();
        JsonNode arr = body.get("reasons");
        if (arr != null && arr.isArray()) {
            for (JsonNode r : arr) {
                String code = Json.str(r, "code");
                if (code != null) reasons.add(new RiskReason(code, Json.str(r, "text") != null ? Json.str(r, "text") : "", null));
            }
        }
        String assurance = Json.str(body, "assurance");
        return new CheckResult(prompt, reasons, assurance != null && ASSURANCE_LEVELS.contains(assurance) ? assurance : "normal",
                "shadow".equals(Json.str(body, "silentMode")) ? "shadow" : "enforce", Json.str(body, "caseCode"));
    }

    /** The browsers Touchque knows for a user (for an "approved browsers" list in your settings page). */
    public JsonNode browsers(String externalUsername) {
        if (externalUsername == null || externalUsername.isEmpty()) throw new TouchqueConfigException("risk.browsers() needs the user (externalUsername)");
        JsonNode list = http.get("/risk/browsers", Map.of("externalUsername", externalUsername)).get("browsers");
        return list != null && list.isArray() ? list : Json.array();
    }

    /**
     * Forgets one browser ({@code thumbprint}, or null for all) of a user: their next sign-in asks the
     * phone again. Call it after a password reset or a sign-out everywhere. Returns how many were forgotten.
     */
    public int forgetBrowsers(String externalUsername, String thumbprint) {
        if (externalUsername == null || externalUsername.isEmpty()) throw new TouchqueConfigException("risk.forgetBrowsers() needs the user (externalUsername)");
        ObjectNode body = Json.object().put("externalUsername", externalUsername);
        Json.put(body, "thumbprint", thumbprint);
        Integer n = Json.integer(http.post("/risk/browsers/forget", body), "forgotten");
        return n == null ? 0 : n;
    }
}
