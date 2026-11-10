package com.touchque.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.touchque.LoginDetail;
import com.touchque.internal.Crypto;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/** Transaction details the way the API normalizes and digests them. */
public final class Details {
    private Details() {
    }

    /** Labels and values trimmed the way the API trims them (JavaScript's {@code trim}), in order. */
    public static List<LoginDetail> normalize(List<LoginDetail> details) {
        List<LoginDetail> out = new ArrayList<>();
        if (details == null) return out;
        for (LoginDetail d : details) {
            out.add(new LoginDetail(d.label() == null ? "" : trim(d.label()), d.value() == null ? "" : trim(d.value())));
        }
        return out;
    }

    /**
     * JavaScript's {@code String.prototype.trim}: Unicode spaces (NBSP, U+FEFF, U+2028…) go too, other
     * control characters stay. {@link String#trim} differs on both, and the digests would not match.
     */
    private static String trim(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && jsSpace(s.charAt(start))) start++;
        while (end > start && jsSpace(s.charAt(end - 1))) end--;
        return s.substring(start, end);
    }

    private static boolean jsSpace(char c) {
        return c == '\t' || c == '\n' || c == '\u000b' || c == '\f' || c == '\r' || c == '\u2028' || c == '\u2029' || c == '\ufeff'
                || Character.getType(c) == Character.SPACE_SEPARATOR;
    }

    /** Details from the API's JSON (a list of {label, value} or an object), normalized. */
    public static List<LoginDetail> fromJson(JsonNode node) {
        List<LoginDetail> list = new ArrayList<>();
        if (node != null && node.isArray()) {
            for (JsonNode d : node) list.add(new LoginDetail(text(d.get("label")), text(d.get("value"))));
        } else if (node != null && node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> it = node.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> e = it.next();
                list.add(new LoginDetail(e.getKey(), text(e.getValue())));
            }
        }
        return normalize(list);
    }

    /**
     * SHA-256 (hex) over the normalized details joined as label US value RS label…; empty for no
     * details. The phone signs this digest ({@link ApprovalProof}).
     */
    public static String digest(List<LoginDetail> details) {
        List<LoginDetail> pairs = normalize(details);
        if (pairs.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < pairs.size(); i++) {
            if (i > 0) sb.append('\u001e');
            sb.append(pairs.get(i).label()).append('\u001f').append(pairs.get(i).value());
        }
        return Crypto.sha256Hex(sb.toString());
    }

    private static String text(JsonNode n) {
        if (n == null || n.isNull()) return "";
        return n.isTextual() ? n.textValue() : n.toString();
    }
}
