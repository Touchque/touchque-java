package com.touchque;

/** The user did not answer in time, or the request expired. */
public class TouchqueTimeoutException extends TouchqueException {
    private final String requestId;

    public TouchqueTimeoutException(String message, String requestId) {
        super(message);
        this.requestId = requestId;
    }

    public String requestId() {
        return requestId;
    }
}
