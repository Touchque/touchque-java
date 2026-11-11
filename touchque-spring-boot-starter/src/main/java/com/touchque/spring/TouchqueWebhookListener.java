package com.touchque.spring;

import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Receives verified webhooks at {@code touchque.webhook.path} (default /webhooks/touchque):
 * <ul>
 * <li>bad signature or too old → 401, the listener is not called;</li>
 * <li>a replay of a delivery already accepted → 200 {@code {"received":true,"duplicate":true}}, not called again;</li>
 * <li>otherwise the listener runs and the answer is 200 {@code {"received":true}} (500 when it throws, so Touchque retries;
 * the jti is released through {@code Webhook.ReplayCache.release}, so the retry runs the listener again).</li>
 * </ul>
 *
 * <pre>{@code
 * @Bean
 * TouchqueWebhookListener webhooks(Sessions sessions) {
 *     return (event, request) -> {
 *         if (Webhook.EVENT_APPROVAL_REVOKED.equals(event.path("event").asText())) sessions.end(event.path("requestId").asText());
 *     };
 * }
 * }</pre>
 */
@FunctionalInterface
public interface TouchqueWebhookListener {
    void onEvent(ObjectNode event, HttpServletRequest request) throws Exception;
}
