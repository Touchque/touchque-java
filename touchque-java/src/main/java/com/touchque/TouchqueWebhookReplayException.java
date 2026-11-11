package com.touchque;

/**
 * A correctly signed webhook with this {@code jti} was already accepted. Usually a Touchque
 * retry of a delivery you processed: answer 200 so it stops, but do not run your side
 * effects again. Extends the signature exception, so existing catch blocks still reject it.
 */
public class TouchqueWebhookReplayException extends TouchqueWebhookSignatureException {
    private final String jti;

    public TouchqueWebhookReplayException(String jti) {
        super("this webhook (jti) was already accepted");
        this.jti = jti;
    }

    public String jti() {
        return jti;
    }
}
