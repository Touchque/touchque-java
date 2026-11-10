package com.touchque;

/** Base class of every exception the TouchQue SDK throws. Unchecked. */
public class TouchQueException extends RuntimeException {
    public TouchQueException(String message) {
        super(message);
    }

    public TouchQueException(String message, Throwable cause) {
        super(message, cause);
    }
}
