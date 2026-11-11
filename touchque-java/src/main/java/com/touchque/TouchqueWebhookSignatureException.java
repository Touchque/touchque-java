package com.touchque;

/** A webhook is not from Touchque, was changed, or is too old. */
public class TouchqueWebhookSignatureException extends TouchqueException {
    public TouchqueWebhookSignatureException(String message) {
        super("Touchque: webhook rejected: " + message);
    }
}
