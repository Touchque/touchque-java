package com.touchque;

import com.fasterxml.jackson.databind.node.ObjectNode;

/** {@code feature_not_in_plan}: the feature is not in the organization's plan. */
public class TouchqueFeatureNotInPlanException extends TouchqueFeatureException {
    public TouchqueFeatureNotInPlanException(int status, ObjectNode body, String message) {
        super(status, body, message, Reason.NOT_IN_PLAN);
    }
}
