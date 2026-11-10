package com.touchque.spring;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** What a guard callback sees: the request and the controller method's resolved arguments. */
public final class TouchQueGuardContext {
    private final HttpServletRequest request;
    private final List<Object> arguments;

    TouchQueGuardContext(HttpServletRequest request, Object[] arguments) {
        this.request = request;
        this.arguments = Collections.unmodifiableList(Arrays.asList(arguments));
    }

    public HttpServletRequest request() {
        return request;
    }

    /** The method's arguments ({@code @RequestBody} included). */
    public List<Object> arguments() {
        return arguments;
    }

    /** The first argument of type {@code type}, e.g. the request body, or null. */
    public <T> T argument(Class<T> type) {
        for (Object a : arguments) {
            if (type.isInstance(a)) return type.cast(a);
        }
        return null;
    }
}
