package com.touchque;

/**
 * An approval token (or a consumed approval) does not say what you are about to execute
 * (another person, action type, amount, recipient…), or it is not a valid token from
 * TouchQue. Do not execute.
 */
public class TouchQueApprovalMismatchException extends TouchQueException {
    public TouchQueApprovalMismatchException(String message) {
        super("TouchQue: " + message);
    }
}
