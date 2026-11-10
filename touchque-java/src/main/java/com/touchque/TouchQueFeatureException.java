package com.touchque;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Json;

/**
 * The organization behind your workspace cannot use this feature here (HTTP 403).
 * {@link #feature()} is the catalog id ({@code device_risk}, {@code ai_agents},
 * {@code mobile_sdk}, {@code ciam}…) and {@link #featureReason()} says why:
 * <ul>
 *   <li>{@link Reason#NOT_IN_PLAN}: not in its plan ({@code feature_not_in_plan}); an
 *       owner or admin adds it in the TouchQue dashboard;</li>
 *   <li>{@link Reason#READ_ONLY}: being turned off ({@code feature_read_only}); reads
 *       still work for 14 days, changes are refused;</li>
 *   <li>{@link Reason#OFF}: switched off on this TouchQue deployment ({@code feature_off}).</li>
 * </ul>
 * A {@link TouchQueApiException}, so existing {@code catch} blocks still see it; catch
 * one of the three subclasses to tell them apart.
 */
public abstract class TouchQueFeatureException extends TouchQueApiException {
    /** Why the feature cannot be used here. */
    public enum Reason { NOT_IN_PLAN, READ_ONLY, OFF }

    private final Reason reason;

    protected TouchQueFeatureException(int status, ObjectNode body, String message, Reason reason) {
        super(status, body, message);
        this.reason = reason;
    }

    /** The catalog id of the feature, or null. */
    public String feature() {
        return Json.str(body(), "feature");
    }

    /** Not in the plan, being turned off (read-only), or switched off on this deployment. */
    public Reason featureReason() {
        return reason;
    }

    /**
     * The exception for an error answer: a {@code TouchQueFeatureException} subclass for
     * the three feature codes, else a {@link TouchQueApiException}.
     */
    public static TouchQueApiException of(int status, ObjectNode body, String message) {
        String error = Json.str(body, "error");
        if ("feature_not_in_plan".equals(error)) return new TouchQueFeatureNotInPlanException(status, body, message);
        if ("feature_read_only".equals(error)) return new TouchQueFeatureReadOnlyException(status, body, message);
        if ("feature_off".equals(error)) return new TouchQueFeatureOffException(status, body, message);
        return new TouchQueApiException(status, body, message);
    }
}
