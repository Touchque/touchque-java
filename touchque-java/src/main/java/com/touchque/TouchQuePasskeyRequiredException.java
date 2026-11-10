package com.touchque;

/**
 * This request must be approved with a passkey. {@link #reason()} is {@code policy} when a
 * phishing-resistant policy requires it (no push was sent), or {@code step_up} when the user
 * tapped Approve on the phone during a call (Vishing Shield) and the request, still open,
 * now waits for a passkey in the browser.
 */
public class TouchQuePasskeyRequiredException extends TouchQueException {
    private final String requestId;
    private final String reason;

    public TouchQuePasskeyRequiredException(String requestId, String reason) {
        super("step_up".equals(reason)
                ? "TouchQue: request '" + requestId + "' must now be approved with a passkey: the user approved on the phone during a call."
                : "TouchQue: request '" + requestId + "' must be approved with a passkey (phishing-resistant policy); no push was sent.");
        this.requestId = requestId;
        this.reason = reason == null ? "policy" : reason;
    }

    public String requestId() {
        return requestId;
    }

    /** {@code policy} or {@code step_up}. */
    public String reason() {
        return reason;
    }
}
