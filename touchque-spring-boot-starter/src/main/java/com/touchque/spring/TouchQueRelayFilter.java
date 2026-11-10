package com.touchque.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Json;
import com.touchque.relay.RelayHandler;
import com.touchque.relay.RelayRequest;
import com.touchque.relay.RelayResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Every relay route a frontend ({@code @touchque/web}) needs under {@code touchque.relay.path}:
 * POST /login, enrollment, offline codes and the passkey ceremonies (see {@link RelayHandler}).
 * It runs after Spring Security, so your callbacks see the signed-in user.
 */
public class TouchQueRelayFilter extends OncePerRequestFilter {
    private static final int MAX_BODY_BYTES = 64 * 1024;
    private final RelayHandler<HttpServletRequest> handler;
    private final String prefix;

    public TouchQueRelayFilter(RelayHandler<HttpServletRequest> handler, String prefix) {
        this.handler = handler;
        String p = "/" + prefix.replaceAll("^/+|/+$", "");
        this.prefix = p.equals("/") ? "" : p;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = Responses.path(request);
        return !(path.equals(prefix) || path.startsWith(prefix + "/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        ObjectNode body = Json.object();
        String contentType = request.getContentType();
        if ("POST".equals(request.getMethod()) && contentType != null && contentType.toLowerCase(Locale.ROOT).startsWith("application/json")) {
            String raw = Responses.body(request, MAX_BODY_BYTES);
            if (raw == null) {
                Responses.error(response, 413, "body_too_large");
                return;
            }
            if (!raw.isBlank()) {
                JsonNode parsed = Json.parse(raw);
                if (parsed == null) {
                    Responses.error(response, 400, "invalid_json");
                    return;
                }
                if (parsed instanceof ObjectNode o) body = o;
            }
        } else if (request.getContentLengthLong() > MAX_BODY_BYTES) {
            Responses.error(response, 413, "body_too_large");
            return;
        }
        String path = Responses.path(request).substring(prefix.length());
        String ip = TouchQueSpring.clientIp(request);
        RelayResponse res = handler.handle(new RelayRequest<>(request.getMethod(), path.isEmpty() ? "/" : path, body, ip != null ? ip : "",
                request.getHeader("User-Agent"), request::getHeader, request));
        if (res == null) {
            Responses.error(response, 404, "not_found");
            return;
        }
        for (Map.Entry<String, String> h : res.headers()) response.addHeader(h.getKey(), h.getValue());
        Responses.json(response, res.status(), res.body());
    }
}
