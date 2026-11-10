package com.touchque.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * One line per protected controller method (or every method of a controller). Until the user
 * approves on their phone this answers {@code 202 {"touchque": step, "token": "..."}}; your page
 * shows the step in its own design and sends the same request again with header
 * {@code X-TouchQue-Token}. Once approved the method runs ONCE; a parameter of type
 * {@link com.touchque.flow.Approval} receives the approval.
 *
 * <pre>{@code
 * @PostMapping("/transfer")
 * @RequireTouchQue("SEND_MONEY")
 * Receipt transfer(@RequestBody Transfer t, Approval approval) { … }
 * }</pre>
 *
 * Who approves is the signed-in user (email, else sub, else name). For transaction details, a
 * login route's user or silent sign-ins, declare a {@link TouchQueGuardOptions} bean for the action.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequireTouchQue {
    /** The action type (LOGIN, SEND_MONEY…). */
    String value();
}
