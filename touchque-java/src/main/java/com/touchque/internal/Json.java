package com.touchque.internal;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.LinkedHashMap;

/** JSON helpers shared by the SDK. Internal API: may change without notice. */
public final class Json {
    /** Unknown fields are ignored; numbers keep their JSON text. */
    public static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS, true);

    /** Like {@link #MAPPER}, but null fields (and null map values) are left out. */
    public static final ObjectMapper NON_NULL_MAPPER = MAPPER.copy()
            .setDefaultPropertyInclusion(JsonInclude.Value.construct(JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL));

    private Json() {
    }

    /** A value as a JSON node with its null fields left out (records of options). */
    public static JsonNode toNodeWithoutNulls(Object value) {
        if (value == null) return null;
        if (value instanceof JsonNode n) return n.deepCopy();
        return NON_NULL_MAPPER.valueToTree(value);
    }

    public static ObjectNode object() {
        return JsonNodeFactory.instance.objectNode();
    }

    public static ArrayNode array() {
        return JsonNodeFactory.instance.arrayNode();
    }

    /** The JSON text of a node ({@code ""} for null). */
    public static String write(JsonNode node) {
        if (node == null) return "";
        try {
            return MAPPER.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A value (record, map, list…) as a JSON node. */
    public static JsonNode toNode(Object value) {
        if (value == null) return null;
        if (value instanceof JsonNode n) return n.deepCopy();
        return MAPPER.valueToTree(value);
    }

    /** Parsed JSON, or null for empty or invalid text. */
    public static JsonNode parse(String text) {
        if (text == null || text.isBlank()) return null;
        try {
            return MAPPER.readTree(text);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    /** Parsed JSON object, or an empty one. */
    public static ObjectNode parseObject(String text) {
        JsonNode n = parse(text);
        return n instanceof ObjectNode o ? o : object();
    }

    /** A string field, or null when missing or not a string. */
    public static String str(JsonNode node, String key) {
        JsonNode v = node == null ? null : node.get(key);
        return v != null && v.isTextual() ? v.textValue() : null;
    }

    public static boolean bool(JsonNode node, String key) {
        JsonNode v = node == null ? null : node.get(key);
        return v != null && v.isBoolean() && v.booleanValue();
    }

    /** JavaScript truthiness of a field (non-empty string, non-zero number, true, object, array). */
    public static boolean truthy(JsonNode node, String key) {
        JsonNode v = node == null ? null : node.get(key);
        if (v == null || v.isNull() || v.isMissingNode()) return false;
        if (v.isBoolean()) return v.booleanValue();
        if (v.isTextual()) return !v.textValue().isEmpty();
        if (v.isNumber()) return v.doubleValue() != 0;
        return true;
    }

    public static Long lng(JsonNode node, String key) {
        JsonNode v = node == null ? null : node.get(key);
        if (v == null) return null;
        if (v.isNumber()) return v.longValue();
        if (v.isTextual()) {
            try {
                return Long.parseLong(v.textValue());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    public static Integer integer(JsonNode node, String key) {
        Long l = lng(node, key);
        return l == null ? null : (int) (long) l;
    }

    /** Adds key = value when value is not null and not empty. */
    public static ObjectNode put(ObjectNode o, String key, String value) {
        if (value != null && !value.isEmpty()) o.put(key, value);
        return o;
    }

    public static ObjectNode put(ObjectNode o, String key, Integer value) {
        if (value != null) o.put(key, value);
        return o;
    }

    public static ObjectNode put(ObjectNode o, String key, Long value) {
        if (value != null) o.put(key, value);
        return o;
    }

    public static ObjectNode put(ObjectNode o, String key, Boolean value) {
        if (value != null) o.put(key, value);
        return o;
    }

    public static ObjectNode putNode(ObjectNode o, String key, JsonNode value) {
        if (value != null) o.set(key, value);
        return o;
    }

    public static ObjectNode putValue(ObjectNode o, String key, Object value) {
        if (value != null) o.set(key, toNode(value));
        return o;
    }

    /** The bytes JSON.stringify would write for a string (quotes included). */
    public static String jsString(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                        sb.append(c).append(s.charAt(++i));
                    } else if (Character.isSurrogate(c)) {
                        // A lone surrogate: well-formed JSON.stringify escapes it.
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }

    /**
     * JSON text without insignificant whitespace; strings and numbers are kept byte for byte
     * (a pretty-printed body from a proxy still canonicalizes).
     */
    public static String compact(String json) {
        StringBuilder sb = new StringBuilder(json.length());
        boolean inString = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                sb.append(c);
                if (c == '\\' && i + 1 < json.length()) {
                    sb.append(json.charAt(++i));
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
                sb.append(c);
            } else if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * The members of a JSON object's top level, each value as its raw text (nested key order and
     * number spelling kept). A later duplicate key wins. Throws IllegalArgumentException when the
     * text is not a JSON object.
     */
    public static LinkedHashMap<String, String> topLevelMembers(String raw) {
        LinkedHashMap<String, String> out = new LinkedHashMap<>();
        int[] pos = {skipWs(raw, 0)};
        if (pos[0] >= raw.length() || raw.charAt(pos[0]) != '{') throw new IllegalArgumentException("not an object");
        pos[0] = skipWs(raw, pos[0] + 1);
        if (pos[0] < raw.length() && raw.charAt(pos[0]) == '}') return out;
        while (true) {
            if (pos[0] >= raw.length() || raw.charAt(pos[0]) != '"') throw new IllegalArgumentException("expected a key");
            int keyEnd = stringEnd(raw, pos[0]);
            String key;
            try {
                key = MAPPER.readValue(raw.substring(pos[0], keyEnd), String.class);
            } catch (JsonProcessingException e) {
                throw new IllegalArgumentException("bad key", e);
            }
            pos[0] = skipWs(raw, keyEnd);
            if (pos[0] >= raw.length() || raw.charAt(pos[0]) != ':') throw new IllegalArgumentException("expected :");
            int valueStart = skipWs(raw, pos[0] + 1);
            int valueEnd = valueEnd(raw, valueStart);
            out.put(key, raw.substring(valueStart, valueEnd).trim());
            pos[0] = skipWs(raw, valueEnd);
            if (pos[0] >= raw.length()) throw new IllegalArgumentException("unterminated object");
            char c = raw.charAt(pos[0]);
            if (c == '}') return out;
            if (c != ',') throw new IllegalArgumentException("expected , or }");
            pos[0] = skipWs(raw, pos[0] + 1);
        }
    }

    private static int skipWs(String s, int i) {
        while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t' || s.charAt(i) == '\n' || s.charAt(i) == '\r')) i++;
        return i;
    }

    /** The index just after the string starting at {@code i} (a quote). */
    private static int stringEnd(String s, int i) {
        for (int j = i + 1; j < s.length(); j++) {
            char c = s.charAt(j);
            if (c == '\\') j++;
            else if (c == '"') return j + 1;
        }
        throw new IllegalArgumentException("unterminated string");
    }

    /** The index just after the value starting at {@code i}. */
    private static int valueEnd(String s, int i) {
        int depth = 0;
        int j = i;
        while (j < s.length()) {
            char c = s.charAt(j);
            if (c == '"') {
                j = stringEnd(s, j);
                if (depth == 0) return j;
                continue;
            }
            if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') {
                if (depth == 0) return j;
                depth--;
                if (depth == 0) return j + 1;
            } else if (c == ',' && depth == 0) {
                return j;
            }
            j++;
        }
        if (depth != 0) throw new IllegalArgumentException("unterminated value");
        return j;
    }
}
