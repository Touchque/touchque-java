package com.touchque.login;

import com.touchque.TouchqueException;

/** A My Account API call failed; {@link #isStepUp()} means the sign-in is too old for it (RFC 9470). */
public class MyAccountException extends TouchqueException {
    private final String errorCode;
    private final int status;
    private final String description;
    private final Integer maxAge;

    public MyAccountException(String errorCode, int status, String description, Integer maxAge) {
        super(description == null ? errorCode : errorCode + ": " + description);
        this.errorCode = errorCode;
        this.status = status;
        this.description = description;
        this.maxAge = maxAge;
    }

    public String errorCode() {
        return errorCode;
    }

    public int status() {
        return status;
    }

    public String description() {
        return description;
    }

    public Integer maxAge() {
        return maxAge;
    }

    /** True when the person must sign in again (authorizationUrl with maxAge 0) before this change. */
    public boolean isStepUp() {
        return "insufficient_user_authentication".equals(errorCode);
    }
}
