package com.touchque;

/**
 * A refused ID-JAG or exchange (Cross App Access). {@link #error()} is the OAuth error:
 * {@code invalid_grant} for a bad ID-JAG, else what the server answered.
 */
public class TouchQueIdJagException extends TouchQueException {
    private final String error;
    private final Integer status;

    public TouchQueIdJagException(String error, String message, Integer status) {
        super(message);
        this.error = error;
        this.status = status;
    }

    public TouchQueIdJagException(String error, String message) {
        this(error, message, null);
    }

    public String error() {
        return error;
    }

    /** The HTTP status the server answered with, when there was one. */
    public Integer status() {
        return status;
    }
}
