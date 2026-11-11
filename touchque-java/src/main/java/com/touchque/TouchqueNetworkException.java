package com.touchque;

/** The request never reached Touchque (DNS, connection refused, timeout). Generally safe to retry. */
public class TouchqueNetworkException extends TouchqueException {
    public TouchqueNetworkException(String message) {
        super("Touchque: network request failed: " + message);
    }

    public TouchqueNetworkException(String message, Throwable cause) {
        super("Touchque: network request failed: " + message, cause);
    }
}
