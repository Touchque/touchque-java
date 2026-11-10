package com.touchque;

/**
 * {@link com.touchque.agents.McpAuth} refused a request: answer with {@link #status()} (401,
 * 403) and the {@code WWW-Authenticate} header in {@link #wwwAuthenticate()}. {@link #error()}
 * is missing_token, invalid_token, invalid_dpop_proof or insufficient_scope.
 */
public class TouchQueMcpAuthException extends TouchQueException {
    private final int status;
    private final String error;
    private final String wwwAuthenticate;

    public TouchQueMcpAuthException(int status, String error, String message, String wwwAuthenticate) {
        super(message);
        this.status = status;
        this.error = error;
        this.wwwAuthenticate = wwwAuthenticate;
    }

    public int status() {
        return status;
    }

    public String error() {
        return error;
    }

    public String wwwAuthenticate() {
        return wwwAuthenticate;
    }
}
