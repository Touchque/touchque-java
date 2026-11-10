package com.touchque;

/** The user rejected the request on their phone. */
public class TouchQueRejectedException extends TouchQueException {
    private final String requestId;

    public TouchQueRejectedException(String requestId) {
        super("TouchQue: request '" + requestId + "' was rejected by the user.");
        this.requestId = requestId;
    }

    public String requestId() {
        return requestId;
    }
}
