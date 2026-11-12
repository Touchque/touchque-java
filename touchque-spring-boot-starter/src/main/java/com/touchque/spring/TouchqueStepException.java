package com.touchque.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.touchque.flow.Guard;

/**
 * Thrown by {@link RequireTouchque} while the user has not approved yet; the starter answers it
 * with {@link #response()}: the step ({@code 202}, or 403/408/423/429…), its headers
 * ({@code Cache-Control: no-store}…) and its JSON body, as {@link Guard#response} builds them.
 */
public class TouchqueStepException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final transient Guard.Result result;
    private final transient Guard.Response response;

    public TouchqueStepException(Guard.Result result) {
        this(result, Guard.response(result, null));
    }

    /** @param body what to send: the guard's body, or for a refusal your {@link TouchqueErrorBody}'s */
    public TouchqueStepException(Guard.Result result, JsonNode body) {
        this(result, withBody(Guard.response(result, null), body));
    }

    /** @param response what to send, from {@link Guard#response} (package-private: {@code new TouchqueStepException(r, null)} stays unambiguous) */
    TouchqueStepException(Guard.Result result, Guard.Response response) {
        super("Touchque: waiting for the user's approval (HTTP " + result.status() + ")", null, false, false);
        this.result = result;
        this.response = response;
    }

    private static Guard.Response withBody(Guard.Response response, JsonNode body) {
        return new Guard.Response(response.status(), response.headers(), body);
    }

    public Guard.Result result() {
        return result;
    }

    /** The status, headers and JSON body to send. */
    public Guard.Response response() {
        return response;
    }

    /** The JSON body to send. */
    public JsonNode body() {
        return response.body();
    }
}
