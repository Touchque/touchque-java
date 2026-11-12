package com.touchque.spring;

import com.touchque.LoginDetail;
import com.touchque.flow.Guard;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * How {@link RequireTouchque} runs for one action. Declare it as a bean:
 *
 * <pre>{@code
 * @Bean
 * TouchqueGuardOptions sendMoney() {
 *     return TouchqueGuardOptions.forAction("SEND_MONEY")
 *         .details(c -> List.of(LoginDetail.of("Amount", c.argument(Transfer.class).amount())));
 * }
 * }</pre>
 */
public final class TouchqueGuardOptions {
    private final String action;
    private Function<TouchqueGuardContext, String> user;
    private Function<TouchqueGuardContext, List<LoginDetail>> details;
    private Function<TouchqueGuardContext, String> referenceId;
    private Function<TouchqueGuardContext, Map<String, Object>> context;
    private Guard.SilentSignIn silentSignIn;
    private boolean enroll = true;
    private TouchqueErrorBody errorBody;

    private TouchqueGuardOptions(String action) {
        this.action = action;
    }

    public static TouchqueGuardOptions forAction(String action) {
        return new TouchqueGuardOptions(action);
    }

    public String action() {
        return action;
    }

    /** Who approves (default: the signed-in user). For a login route, return whoever just passed your password check. */
    public TouchqueGuardOptions user(Function<TouchqueGuardContext, String> v) {
        this.user = v;
        return this;
    }

    /** Transaction details shown on the phone. Build them from server-side state or validated input. */
    public TouchqueGuardOptions details(Function<TouchqueGuardContext, List<LoginDetail>> v) {
        this.details = v;
        return this;
    }

    public TouchqueGuardOptions referenceId(Function<TouchqueGuardContext, String> v) {
        this.referenceId = v;
        return this;
    }

    /** For your Touchque Actions only ({@code event.context}): roles, plan, amount… Never shown on the phone. */
    public TouchqueGuardOptions context(Function<TouchqueGuardContext, Map<String, Object>> v) {
        this.context = v;
        return this;
    }

    /**
     * Silent sign-ins (default off): a new attempt whose browser sent its device-bound key proof
     * ({@code X-Touchque-Browser}) first asks Touchque whether anything is new; if nothing is, the
     * method runs at once with no push.
     */
    public TouchqueGuardOptions silentSignIn(Guard.SilentSignIn v) {
        this.silentSignIn = v;
        return this;
    }

    /**
     * False: never show the first-time linking QR. A user with no phone then gets 202
     * {@code {"state": "enroll", "reason": "enrollment_off"}}.
     */
    public TouchqueGuardOptions enroll(boolean v) {
        this.enroll = v;
        return this;
    }

    /** Your own body for this action's refusals (400 or more), instead of the {@link TouchqueErrorBody} bean's or the default one. */
    public TouchqueGuardOptions errorBody(TouchqueErrorBody v) {
        this.errorBody = v;
        return this;
    }

    Function<TouchqueGuardContext, String> user() {
        return user;
    }

    Function<TouchqueGuardContext, List<LoginDetail>> details() {
        return details;
    }

    Function<TouchqueGuardContext, String> referenceId() {
        return referenceId;
    }

    Function<TouchqueGuardContext, Map<String, Object>> context() {
        return context;
    }

    Guard.SilentSignIn silentSignIn() {
        return silentSignIn;
    }

    boolean enroll() {
        return enroll;
    }

    TouchqueErrorBody errorBody() {
        return errorBody;
    }
}
