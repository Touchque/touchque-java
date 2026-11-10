package com.touchque;

/** The request never reached TouchQue (DNS, connection refused, timeout). Generally safe to retry. */
public class TouchQueNetworkException extends TouchQueException {
    public TouchQueNetworkException(String message) {
        super("TouchQue: network request failed: " + message);
    }

    public TouchQueNetworkException(String message, Throwable cause) {
        super("TouchQue: network request failed: " + message, cause);
    }
}
