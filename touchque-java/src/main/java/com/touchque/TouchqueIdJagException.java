package com.touchque;

/**
 * A refused ID-JAG or exchange (Cross App Access). {@link #error()} is the OAuth error:
 * {@code invalid_grant} for a bad ID-JAG, else what the server answered. {@link #dpopNonce()} is the
 * latest valid DPoP-Nonce the server sent during the call, when it sent one.
 */
public class TouchqueIdJagException extends TouchqueException {
    private final String error;
    private final Integer status;
    private final String dpopNonce;

    public TouchqueIdJagException(String error, String message, Integer status, String dpopNonce) {
        super(message);
        this.error = error;
        this.status = status;
        this.dpopNonce = dpopNonce;
    }

    public TouchqueIdJagException(String error, String message, Integer status) {
        this(error, message, status, null);
    }

    public TouchqueIdJagException(String error, String message) {
        this(error, message, null, null);
    }

    public String error() {
        return error;
    }

    /** The HTTP status the server answered with, when there was one. */
    public Integer status() {
        return status;
    }

    /**
     * The latest {@code DPoP-Nonce} the server sent during the call (RFC 9449 section 8), or null: after a nonce retry
     * the second answer's when it carried one, else the first answer's. Only a value in RFC 9449 nonce syntax
     * (printable ASCII except space, '"' and '\'), never one from a missing, empty, invalid or conflicting header. With a
     * DPoP key, a request refused with use_dpop_nonce and a valid nonce was already sent once more with it. To try
     * again yourself, put it in a new proof: {@code CrossAppAccess.idJagDpopProof(key, "POST", url, null, nonce)}.
     */
    public String dpopNonce() {
        return dpopNonce;
    }
}
