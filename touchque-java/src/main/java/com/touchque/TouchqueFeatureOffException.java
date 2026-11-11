package com.touchque;

import com.fasterxml.jackson.databind.node.ObjectNode;

/** {@code feature_off}: the feature is switched off on this Touchque deployment. */
public class TouchqueFeatureOffException extends TouchqueFeatureException {
    public TouchqueFeatureOffException(int status, ObjectNode body, String message) {
        super(status, body, message, Reason.OFF);
    }
}
