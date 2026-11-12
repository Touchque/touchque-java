package com.touchque.spring;

import com.touchque.TouchqueMcpAuthException;
import com.touchque.flow.Guard;
import com.touchque.internal.Json;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Turns the guard's step and refused MCP tokens into their HTTP answers. */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TouchqueExceptionHandler {
    @ExceptionHandler(TouchqueStepException.class)
    public ResponseEntity<String> step(TouchqueStepException e) {
        Guard.Result r = e.result();
        ResponseEntity.BodyBuilder res = ResponseEntity.status(r.status()).contentType(MediaType.APPLICATION_JSON).header(HttpHeaders.CACHE_CONTROL, "no-store");
        if (r.retryAfter() != null) res.header(HttpHeaders.RETRY_AFTER, r.retryAfter().toString());
        r.refusalHeaders().forEach(res::header);
        String body;
        try {
            body = Json.write(e.body() != null ? e.body() : r.body());
        } catch (RuntimeException | StackOverflowError unwritable) {
            // A last resort (the guard already wrote an errorBody's result once): the guard's own body.
            body = Json.write(r.body());
        }
        return res.body(body);
    }

    @ExceptionHandler(TouchqueMcpAuthException.class)
    public ResponseEntity<String> mcp(TouchqueMcpAuthException e) {
        return ResponseEntity.status(e.status()).contentType(MediaType.APPLICATION_JSON).header(HttpHeaders.WWW_AUTHENTICATE, e.wwwAuthenticate())
                .body(Json.write(Json.object().put("error", e.error()).put("error_description", e.getMessage())));
    }
}
