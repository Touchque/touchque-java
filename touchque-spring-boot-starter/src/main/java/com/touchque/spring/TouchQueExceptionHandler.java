package com.touchque.spring;

import com.touchque.TouchQueMcpAuthException;
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
public class TouchQueExceptionHandler {
    @ExceptionHandler(TouchQueStepException.class)
    public ResponseEntity<String> step(TouchQueStepException e) {
        Guard.Result r = e.result();
        ResponseEntity.BodyBuilder res = ResponseEntity.status(r.status()).contentType(MediaType.APPLICATION_JSON).header(HttpHeaders.CACHE_CONTROL, "no-store");
        if (r.retryAfter() != null) res.header(HttpHeaders.RETRY_AFTER, r.retryAfter().toString());
        return res.body(Json.write(r.body()));
    }

    @ExceptionHandler(TouchQueMcpAuthException.class)
    public ResponseEntity<String> mcp(TouchQueMcpAuthException e) {
        return ResponseEntity.status(e.status()).contentType(MediaType.APPLICATION_JSON).header(HttpHeaders.WWW_AUTHENTICATE, e.wwwAuthenticate())
                .body(Json.write(Json.object().put("error", e.error()).put("error_description", e.getMessage())));
    }
}
