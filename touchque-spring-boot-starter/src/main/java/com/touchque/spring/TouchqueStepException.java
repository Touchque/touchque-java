package com.touchque.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.touchque.flow.Guard;

/**
 * Thrown by {@link RequireTouchque} while the user has not approved yet; the starter answers it
 * with the step ({@code 202}, or 403/408/423/429…) and {@code Cache-Control: no-store}.
 */
public class TouchqueStepException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final transient Guard.Result result;
    private final transient JsonNode body;

    public TouchqueStepException(Guard.Result result) {
        this(result, result.body());
    }

    /** @param body what to send: the guard's body, or for a refusal your {@link TouchqueErrorBody}'s */
    public TouchqueStepException(Guard.Result result, JsonNode body) {
        super("Touchque: waiting for the user's approval (HTTP " + result.status() + ")", null, false, false);
        this.result = result;
        this.body = body;
    }

    public Guard.Result result() {
        return result;
    }

    /** The JSON body to send. */
    public JsonNode body() {
        return body;
    }
}
