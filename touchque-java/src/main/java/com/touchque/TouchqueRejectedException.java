package com.touchque;

/** The user rejected the request on their phone. */
public class TouchqueRejectedException extends TouchqueException {
    private final String requestId;

    public TouchqueRejectedException(String requestId) {
        super("Touchque: request '" + requestId + "' was rejected by the user.");
        this.requestId = requestId;
    }

    public String requestId() {
        return requestId;
    }
}
