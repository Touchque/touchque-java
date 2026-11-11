package com.touchque;

/**
 * An approval token (or a consumed approval) does not say what you are about to execute
 * (another person, action type, amount, recipient…), or it is not a valid token from
 * Touchque. Do not execute.
 */
public class TouchqueApprovalMismatchException extends TouchqueException {
    public TouchqueApprovalMismatchException(String message) {
        super("Touchque: " + message);
    }
}
