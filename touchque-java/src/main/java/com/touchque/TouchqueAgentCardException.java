package com.touchque;

/**
 * An A2A agent card that did not verify. {@link #error()} is unsigned, malformed,
 * untrusted_key, invalid_signature or keys_unavailable.
 */
public class TouchqueAgentCardException extends TouchqueException {
    private final String error;

    public TouchqueAgentCardException(String error, String message) {
        super(message);
        this.error = error;
    }

    public String error() {
        return error;
    }
}
