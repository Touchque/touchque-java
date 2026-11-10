package com.touchque.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.touchque.internal.Json;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** JSON answers and bounded bodies for the starter's filters. */
final class Responses {
    private Responses() {
    }

    static void json(HttpServletResponse response, int status, JsonNode body) throws IOException {
        byte[] bytes = Json.write(body).getBytes(StandardCharsets.UTF_8);
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
    }

    static void error(HttpServletResponse response, int status, String error) throws IOException {
        json(response, status, Json.object().put("error", error));
    }

    /** The body as UTF-8 text, or null when it is longer than {@code max} bytes. */
    static String body(HttpServletRequest request, int max) throws IOException {
        if (request.getContentLengthLong() > max) return null;
        try (InputStream in = request.getInputStream(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[8192];
            int read;
            while ((read = in.read(chunk)) > 0) {
                if (out.size() + read > max) return null;
                out.write(chunk, 0, read);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    /** The request path inside the application (without the context path). */
    static String path(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String ctx = request.getContextPath();
        return ctx != null && !ctx.isEmpty() && uri.startsWith(ctx) ? uri.substring(ctx.length()) : uri;
    }
}
