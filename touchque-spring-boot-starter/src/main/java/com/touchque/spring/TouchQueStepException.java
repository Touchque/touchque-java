package com.touchque.spring;

import com.touchque.flow.Guard;

/**
 * Thrown by {@link RequireTouchQue} while the user has not approved yet; the starter answers it
 * with the step ({@code 202}, or 403/408/423/429…) and {@code Cache-Control: no-store}.
 */
public class TouchQueStepException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final transient Guard.Result result;

    public TouchQueStepException(Guard.Result result) {
        super("TouchQue: waiting for the user's approval (HTTP " + result.status() + ")", null, false, false);
        this.result = result;
    }

    public Guard.Result result() {
        return result;
    }
}
