package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.LoginDetail;
import com.touchque.TouchQueConfigException;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Never Locked Out: move a user whose phone is lost, dead or replaced to a new phone without a help desk.
 * <ol>
 * <li>Let users name colleagues who can vouch for them ({@link #setVouchers}), behind an approval on their phone.</li>
 * <li>When the phone is gone, after the password (or your IdP): {@link #start}. Show {@code bindUri} as a QR for the
 * TouchQue app on the new phone, then poll {@link #status} and show each voucher's {@code code}: the user reads it
 * to the colleague on a call, who types it on their own phone.</li>
 * <li>After a cooling-off nobody vetoed, the account is on the new phone ({@code COMPLETED}); critical actions wait 24 h.</li>
 * </ol>
 * Admins can stop a running recovery with {@link #veto}.
 */
public final class Recovery {
    /** Statuses of a recovery still waiting for the new phone, the vouchers or the cooling-off. */
    public static final List<String> OPEN_STATUSES = List.of("AWAITING_DEVICE", "VOUCHING", "COOLING");

    private final TouchQueHttp http;

    /** Internal: use {@code tq.recovery()}. */
    public Recovery(TouchQueHttp http) {
        this.http = http;
    }

    /** True while a recovery waits for the new phone, the vouchers or the cooling-off. */
    public static boolean isOpen(JsonNode recovery) {
        return OPEN_STATUSES.contains(Json.str(recovery, "status"));
    }

    /** The colleagues a user named, and whether each can vouch today. */
    public JsonNode vouchers(String externalUsername) {
        require("vouchers", "externalUsername", externalUsername);
        return http.get("/recovery/vouchers", Map.of("externalUsername", externalUsername));
    }

    /** Replaces the user's vouchers (at most 5 are kept). Ask for the user's phone first: whoever sets them chooses who may move the account. */
    public JsonNode setVouchers(String externalUsername, List<String> vouchers) {
        require("setVouchers", "externalUsername", externalUsername);
        ObjectNode body = Json.object().put("externalUsername", externalUsername);
        ArrayNode list = Json.array();
        vouchers.forEach(list::add);
        body.set("vouchers", list);
        return http.post("/recovery/vouchers", body);
    }

    /** What {@link #start} needs. */
    public static final class StartOptions {
        private final String externalUsername;
        private String clientIp;
        private String userAgent;
        private String displayName;
        private List<String> fallbackVouchers;
        private Integer required;
        private Integer coolOffMinutes;
        private List<LoginDetail> details;
        private List<LoginDetail> noticeDetails;

        public StartOptions(String externalUsername) {
            this.externalUsername = externalUsername;
        }

        public StartOptions clientIp(String v) {
            this.clientIp = v;
            return this;
        }

        public StartOptions userAgent(String v) {
            this.userAgent = v;
            return this;
        }

        public StartOptions displayName(String v) {
            this.displayName = v;
            return this;
        }

        /** Fill up a short named list, e.g. with the organization's admins. */
        public StartOptions fallbackVouchers(List<String> v) {
            this.fallbackVouchers = v;
            return this;
        }

        /** Raise the floor of 2 vouchers. */
        public StartOptions required(Integer v) {
            this.required = v;
            return this;
        }

        /** Raise the floor of 15 minutes. */
        public StartOptions coolOffMinutes(Integer v) {
            this.coolOffMinutes = v;
            return this;
        }

        /** What the vouchers' phones show. */
        public StartOptions details(List<LoginDetail> v) {
            this.details = v;
            return this;
        }

        /** What the old phone shows (approve to move now, reject to stop). */
        public StartOptions noticeDetails(List<LoginDetail> v) {
            this.noticeDetails = v;
            return this;
        }
    }

    /**
     * Starts moving the user to a new phone. Call it only after the first factor. Throws
     * {@link com.touchque.TouchQueApiException} with code not_enough_vouchers, recovery_in_progress,
     * blocked, frozen or rate_limited.
     */
    public JsonNode start(StartOptions o) {
        require("start", "the user (externalUsername)", o.externalUsername);
        if ((o.required != null && o.required < 1) || (o.coolOffMinutes != null && o.coolOffMinutes < 1)) {
            throw new TouchQueConfigException("recovery.start(): required and coolOffMinutes must be positive integers");
        }
        ObjectNode body = Json.object().put("externalUsername", o.externalUsername);
        Json.put(body, "clientIp", o.clientIp);
        Json.put(body, "userAgent", o.userAgent);
        Json.put(body, "displayName", o.displayName);
        if (o.fallbackVouchers != null && !o.fallbackVouchers.isEmpty()) body.set("fallbackVouchers", Json.toNode(o.fallbackVouchers));
        Json.put(body, "required", o.required);
        Json.put(body, "coolOffMinutes", o.coolOffMinutes);
        if (o.details != null && !o.details.isEmpty()) body.set("details", LoginRequestOptions.detailsJson(o.details));
        if (o.noticeDetails != null && !o.noticeDetails.isEmpty()) body.set("noticeDetails", LoginRequestOptions.detailsJson(o.noticeDetails));
        return http.post("/recovery/start", body);
    }

    /** The recovery now, with its receipt chain. Poll it while the user waits. */
    public JsonNode status(String recoveryId) {
        require("status", "recoveryId", recoveryId);
        return http.get("/recovery/" + TouchQueHttp.seg(recoveryId));
    }

    /** A user's recoveries, or ({@code open}) every running one of your workspace: the {@code recoveries} array. */
    public JsonNode list(String externalUsername, boolean open) {
        if ((externalUsername == null || externalUsername.isEmpty()) && !open) {
            throw new TouchQueConfigException("recovery.list() needs externalUsername or open: true");
        }
        Map<String, String> q = new HashMap<>();
        if (externalUsername != null && !externalUsername.isEmpty()) q.put("externalUsername", externalUsername);
        if (open) q.put("open", "true");
        JsonNode list = http.get("/recovery", q).get("recoveries");
        return list != null && list.isArray() ? list : Json.array();
    }

    /** Stops a running recovery (e.g. an admin who does not believe it). Does not freeze the user. */
    public JsonNode veto(String recoveryId, String by, String reason) {
        require("veto", "recoveryId", recoveryId);
        ObjectNode body = Json.object();
        Json.put(body, "by", by);
        Json.put(body, "reason", reason);
        return http.post("/recovery/" + TouchQueHttp.seg(recoveryId) + "/veto", body);
    }

    private static void require(String method, String what, String value) {
        if (value == null || value.isEmpty()) throw new TouchQueConfigException("recovery." + method + "() needs " + what);
    }
}
