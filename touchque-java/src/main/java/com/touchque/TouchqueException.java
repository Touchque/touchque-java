package com.touchque;

/** Base class of every exception the Touchque SDK throws. Unchecked. */
public class TouchqueException extends RuntimeException {
    public TouchqueException(String message) {
        super(message);
    }

    public TouchqueException(String message, Throwable cause) {
        super(message, cause);
    }
}
