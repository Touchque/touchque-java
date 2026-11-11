package com.touchque;

/** Missing or invalid configuration, an undefined action type, or a wrong argument. */
public class TouchqueConfigException extends TouchqueException {
    public TouchqueConfigException(String message) {
        super("Touchque config error: " + message);
    }
}
