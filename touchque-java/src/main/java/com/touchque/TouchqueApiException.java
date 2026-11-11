package com.touchque;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Json;

/**
 * The API answered with an error (status 400 or more). {@link #status()} is the HTTP
 * status, {@link #code()} the machine-readable code ({@code device_not_linked},
 * {@code unknown_action}, {@code already_used}…) and {@link #body()} the decoded JSON body.
 */
public class TouchqueApiException extends TouchqueException {
    private final int status;
    private final ObjectNode body;

    public TouchqueApiException(int status, ObjectNode body) {
        this(status, body, null);
    }

    public TouchqueApiException(int status, ObjectNode body, String message) {
        super(message != null ? message : firstNonNull(Json.str(body, "message"), Json.str(body, "error"), "Touchque API error: HTTP " + status));
        this.status = status;
        this.body = body != null ? body : Json.object();
    }

    private static String firstNonNull(String... values) {
        for (String v : values) {
            if (v != null) return v;
        }
        return null;
    }

    /** HTTP status code (404, 409, 423, 429…). */
    public int status() {
        return status;
    }

    /** The decoded JSON body of the error. */
    public ObjectNode body() {
        return body;
    }

    /** Machine-readable error code, e.g. {@code device_not_linked}. */
    public String code() {
        return Json.str(body, "code");
    }

    /** The API's {@code error} field. */
    public String error() {
        return Json.str(body, "error");
    }

    /** Why a request was refused (offline codes, blocked requests). */
    public String reason() {
        return Json.str(body, "reason");
    }

    /** Offline sign: wrong codes left before the challenge locks. */
    public Integer attemptsLeft() {
        return Json.integer(body, "attemptsLeft");
    }

    /** Seconds to wait before retrying (429 / 423), from the body or the Retry-After header. */
    public Integer retryAfter() {
        return Json.integer(body, "retryAfter");
    }

    /**
     * "Why?" case code of a refusal ({@code K7P-2QX}): show it to the user ("Tell your
     * support team: K7P-2QX"); your team opens the decision by it in the dashboard.
     */
    public String caseCode() {
        return Json.str(body, "caseCode");
    }

    /** Where to send the person instead (help desk: {@code never_locked_out}). */
    public String route() {
        return Json.str(body, "route");
    }
}
