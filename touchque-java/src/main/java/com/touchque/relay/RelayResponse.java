package com.touchque.relay;

import com.fasterxml.jackson.databind.JsonNode;
import com.touchque.internal.Json;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * What the relay wants sent back: a status, a JSON body and headers. {@code onAuthenticated}
 * receives the pending success response and may change it (e.g. add a Set-Cookie); the handler sets
 * the body afterwards.
 */
public final class RelayResponse {
    private final List<Map.Entry<String, String>> headers = new ArrayList<>();
    private int status;
    private JsonNode body;

    public RelayResponse(int status, JsonNode body) {
        this.status = status;
        this.body = body != null ? body : Json.object();
    }

    public RelayResponse(int status) {
        this(status, null);
    }

    public int status() {
        return status;
    }

    public RelayResponse status(int v) {
        this.status = v;
        return this;
    }

    /** Always a JSON object on the wire. */
    public JsonNode body() {
        return body;
    }

    public RelayResponse body(JsonNode v) {
        this.body = v;
        return this;
    }

    public List<Map.Entry<String, String>> headers() {
        return Collections.unmodifiableList(headers);
    }

    /** Sets a header, replacing any value it had. */
    public RelayResponse setHeader(String name, String value) {
        headers.removeIf(h -> h.getKey().equalsIgnoreCase(name));
        headers.add(new AbstractMap.SimpleImmutableEntry<>(name, value));
        return this;
    }

    /** Adds a header value, keeping existing ones (several Set-Cookie). */
    public RelayResponse addHeader(String name, String value) {
        headers.add(new AbstractMap.SimpleImmutableEntry<>(name, value));
        return this;
    }

    public String header(String name) {
        for (Map.Entry<String, String> h : headers) {
            if (h.getKey().equalsIgnoreCase(name)) return h.getValue();
        }
        return null;
    }
}
