package com.touchque;

/**
 * A refused Security Event Token (Shared Signals). {@link #error()} is the RFC 8935 error to
 * answer with (HTTP 400 {@code {"err": error}}): invalid_request, invalid_key, invalid_issuer or
 * invalid_audience; temporarily_unavailable when the issuer's keys could not be read (answer 503:
 * the transmitter tries again).
 */
public class TouchQueSecurityEventException extends TouchQueException {
    private final String error;

    public TouchQueSecurityEventException(String error, String message) {
        super(message);
        this.error = error;
    }

    public String error() {
        return error;
    }
}
