package com.touchque.login;

import com.touchque.TouchQueException;

/** A sign-in or token check failed; {@link #errorCode()} is machine-readable. */
public class HostedLoginException extends TouchQueException {
    private final String errorCode;
    private final String description;
    private final Integer status;

    public HostedLoginException(String errorCode, String description, Integer status) {
        super(description == null ? errorCode : errorCode + ": " + description);
        this.errorCode = errorCode;
        this.description = description;
        this.status = status;
    }

    public HostedLoginException(String errorCode, String description) {
        this(errorCode, description, null);
    }

    /** state_mismatch, issuer_mismatch, nonce_mismatch, invalid_token, insufficient_scope, invalid_grant, access_denied… */
    public String errorCode() {
        return errorCode;
    }

    public String description() {
        return description;
    }

    public Integer status() {
        return status;
    }
}
