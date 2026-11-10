package com.touchque;

import com.fasterxml.jackson.databind.node.ObjectNode;

/** {@code feature_off}: the feature is switched off on this TouchQue deployment. */
public class TouchQueFeatureOffException extends TouchQueFeatureException {
    public TouchQueFeatureOffException(int status, ObjectNode body, String message) {
        super(status, body, message, Reason.OFF);
    }
}
