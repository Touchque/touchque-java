package com.touchque;

/** A webhook is not from TouchQue, was changed, or is too old. */
public class TouchQueWebhookSignatureException extends TouchQueException {
    public TouchQueWebhookSignatureException(String message) {
        super("TouchQue: webhook rejected: " + message);
    }
}
