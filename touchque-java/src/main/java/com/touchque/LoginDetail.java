package com.touchque;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * One line of transaction context on the approval screen, e.g. {@code LoginDetail.of("Amount", "1,250.00 USD")}.
 * Shown in order. At most 8 lines, labels up to 40 and values up to 120 characters; the API
 * rejects (never truncates) anything longer. Build them from server-side state, never from browser input.
 */
public record LoginDetail(String label, String value) {
    public static LoginDetail of(String label, String value) {
        return new LoginDetail(label, value);
    }

    /** Lines from a map, in its iteration order (use a LinkedHashMap). */
    public static List<LoginDetail> fromMap(Map<String, String> pairs) {
        List<LoginDetail> out = new ArrayList<>();
        pairs.forEach((k, v) -> out.add(new LoginDetail(k, v)));
        return out;
    }
}
