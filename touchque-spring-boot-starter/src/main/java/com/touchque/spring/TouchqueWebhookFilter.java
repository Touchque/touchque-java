package com.touchque.spring;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueClient;
import com.touchque.TouchqueWebhookReplayException;
import com.touchque.TouchqueWebhookSignatureException;
import com.touchque.internal.Json;
import com.touchque.resources.Webhook;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * The webhook endpoint: reads the raw body, checks the signature, the timestamp and the jti, then
 * calls the {@link TouchqueWebhookListener}. It runs before Spring Security: the signature is the
 * authentication, and Touchque sends no CSRF token.
 */
public class TouchqueWebhookFilter extends OncePerRequestFilter {
    private static final int MAX_BODY_BYTES = 1024 * 1024;
    private final TouchqueClient client;
    private final Webhook.ReplayCache cache;
    private final TouchqueWebhookListener listener;
    private final String path;
    private final int toleranceSeconds;

    public TouchqueWebhookFilter(TouchqueClient client, Webhook.ReplayCache cache, TouchqueWebhookListener listener, String path, int toleranceSeconds) {
        this.client = client;
        this.cache = cache;
        this.listener = listener;
        this.path = path;
        this.toleranceSeconds = toleranceSeconds;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !path.equals(Responses.path(request));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        if (!"POST".equals(request.getMethod())) {
            response.setHeader("Allow", "POST");
            Responses.error(response, 405, "method_not_allowed");
            return;
        }
        String raw = Responses.body(request, MAX_BODY_BYTES);
        ObjectNode event;
        try {
            if (raw == null) throw new TouchqueWebhookSignatureException("body too large");
            event = client.webhook().verify(raw, request.getHeader("x-signature"), toleranceSeconds, cache);
        } catch (TouchqueWebhookReplayException e) {
            Responses.json(response, 200, Json.object().put("received", true).put("duplicate", true));
            return;
        } catch (TouchqueWebhookSignatureException e) {
            Responses.error(response, 401, "invalid_signature");
            return;
        }
        try {
            listener.onEvent(event, request);
        } catch (IOException | ServletException | RuntimeException e) {
            release(event);
            throw e;
        } catch (Exception e) {
            release(event);
            throw new ServletException(e);
        }
        if (!response.isCommitted()) Responses.json(response, 200, Json.object().put("received", true));
    }

    /** The listener failed: forget the jti so Touchque's retry of this delivery runs it again instead of being a duplicate. */
    private void release(ObjectNode event) {
        if (cache != null) cache.release(Json.str(event, "jti"));
    }
}
