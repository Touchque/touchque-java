package com.touchque;

/** The user did not answer in time, or the request expired. */
public class TouchQueTimeoutException extends TouchQueException {
    private final String requestId;

    public TouchQueTimeoutException(String message, String requestId) {
        super(message);
        this.requestId = requestId;
    }

    public String requestId() {
        return requestId;
    }
}
