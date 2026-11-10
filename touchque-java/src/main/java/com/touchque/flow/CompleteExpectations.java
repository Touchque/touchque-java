package com.touchque.flow;

import com.touchque.LoginDetail;
import java.util.List;

/** What an approved request must be for (checked by {@code TouchQueClient.complete}). */
public record CompleteExpectations(String user, String action, List<LoginDetail> details, String referenceId) {
    public static CompleteExpectations of(String user, String action) {
        return new CompleteExpectations(user, action, null, null);
    }
}
