package com.touchque;

/** Missing or invalid configuration, an undefined action type, or a wrong argument. */
public class TouchQueConfigException extends TouchQueException {
    public TouchQueConfigException(String message) {
        super("TouchQue config error: " + message);
    }
}
