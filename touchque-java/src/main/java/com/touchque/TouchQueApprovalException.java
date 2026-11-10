package com.touchque;

/**
 * An AI agent's approval ended without a usable approval: {@link #status()} is rejected,
 * blocked, revoked, expired, stale (approved too long ago) or redeemed (already used).
 */
public class TouchQueApprovalException extends TouchQueException {
    private final String approvalId;
    private final String status;
    private final String reason;

    public TouchQueApprovalException(String approvalId, String status, String reason) {
        super("TouchQue: approval '" + approvalId + "' is " + status + (reason == null ? "." : " (" + reason + ")."));
        this.approvalId = approvalId;
        this.status = status;
        this.reason = reason;
    }

    public String approvalId() {
        return approvalId;
    }

    public String status() {
        return status;
    }

    public String reason() {
        return reason;
    }
}
