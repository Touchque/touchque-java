package com.touchque;

import com.fasterxml.jackson.databind.node.ObjectNode;

/** {@code feature_read_only}: the feature is being turned off; reads work, changes are refused. */
public class TouchQueFeatureReadOnlyException extends TouchQueFeatureException {
    public TouchQueFeatureReadOnlyException(int status, ObjectNode body, String message) {
        super(status, body, message, Reason.READ_ONLY);
    }
}
