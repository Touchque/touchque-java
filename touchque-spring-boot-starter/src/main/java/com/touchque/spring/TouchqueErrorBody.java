package com.touchque.spring;

import com.touchque.flow.Guard;

/**
 * Your app's own JSON body for the answers {@link RequireTouchque} refuses with (status 400 or
 * more: 401, 403, 408, 423, 429, 500, 503). Never called for a 202 step or on approval. Declare it
 * as a bean for every guarded method, or set it for one action with
 * {@link TouchqueGuardOptions#errorBody}:
 *
 * <pre>{@code
 * @Bean
 * TouchqueErrorBody touchqueErrors() {
 *     return r -> Map.of("message", r.message(), "code", r.code());
 * }
 * }</pre>
 *
 * What it returns is written with your app's ObjectMapper. When that gives a JSON object (a Map, a
 * record, a bean, an ObjectNode), it is sent with {@code touchque} set to the step, so
 * {@code @touchque/web} still sees the state; no token is added. Anything else (a String, a number,
 * a List, null) is sent as it is. The status and the headers stay the same ({@code Cache-Control:
 * no-store}, {@code Retry-After}, {@code X-Touchque-State}, {@code X-Touchque-Reason}). When it
 * throws, or returns what the ObjectMapper cannot write, the default body is sent and
 * {@code [Touchque] errorBody failed: <message>} is logged. It gets a copy of the step. With two
 * such beans and none {@code @Primary}, refusals keep the default body. It is a
 * {@link Guard.ErrorBody}: a guard inside your handler gets the same answer with
 * {@code Guard.response(result, errorBody, objectMapper, logger)} and your app's ObjectMapper
 * (the two-argument form writes with the SDK's own ObjectMapper and logs nothing).
 */
@FunctionalInterface
public interface TouchqueErrorBody extends Guard.ErrorBody {
    @Override
    Object body(Guard.Refusal refusal);
}
