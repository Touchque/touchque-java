package com.touchque.spring;

import com.touchque.LoginDetail;
import com.touchque.flow.Guard;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * How {@link RequireTouchQue} runs for one action. Declare it as a bean:
 *
 * <pre>{@code
 * @Bean
 * TouchQueGuardOptions sendMoney() {
 *     return TouchQueGuardOptions.forAction("SEND_MONEY")
 *         .details(c -> List.of(LoginDetail.of("Amount", c.argument(Transfer.class).amount())));
 * }
 * }</pre>
 */
public final class TouchQueGuardOptions {
    private final String action;
    private Function<TouchQueGuardContext, String> user;
    private Function<TouchQueGuardContext, List<LoginDetail>> details;
    private Function<TouchQueGuardContext, String> referenceId;
    private Function<TouchQueGuardContext, Map<String, Object>> context;
    private Guard.SilentSignIn silentSignIn;
    private boolean enroll = true;

    private TouchQueGuardOptions(String action) {
        this.action = action;
    }

    public static TouchQueGuardOptions forAction(String action) {
        return new TouchQueGuardOptions(action);
    }

    public String action() {
        return action;
    }

    /** Who approves (default: the signed-in user). For a login route, return whoever just passed your password check. */
    public TouchQueGuardOptions user(Function<TouchQueGuardContext, String> v) {
        this.user = v;
        return this;
    }

    /** Transaction details shown on the phone. Build them from server-side state or validated input. */
    public TouchQueGuardOptions details(Function<TouchQueGuardContext, List<LoginDetail>> v) {
        this.details = v;
        return this;
    }

    public TouchQueGuardOptions referenceId(Function<TouchQueGuardContext, String> v) {
        this.referenceId = v;
        return this;
    }

    /** For your TouchQue Actions only ({@code event.context}): roles, plan, amount… Never shown on the phone. */
    public TouchQueGuardOptions context(Function<TouchQueGuardContext, Map<String, Object>> v) {
        this.context = v;
        return this;
    }

    /**
     * Silent sign-ins (default off): a new attempt whose browser sent its device-bound key proof
     * ({@code X-TouchQue-Browser}) first asks TouchQue whether anything is new; if nothing is, the
     * method runs at once with no push.
     */
    public TouchQueGuardOptions silentSignIn(Guard.SilentSignIn v) {
        this.silentSignIn = v;
        return this;
    }

    /** False: never show the first-time linking QR. */
    public TouchQueGuardOptions enroll(boolean v) {
        this.enroll = v;
        return this;
    }

    Function<TouchQueGuardContext, String> user() {
        return user;
    }

    Function<TouchQueGuardContext, List<LoginDetail>> details() {
        return details;
    }

    Function<TouchQueGuardContext, String> referenceId() {
        return referenceId;
    }

    Function<TouchQueGuardContext, Map<String, Object>> context() {
        return context;
    }

    Guard.SilentSignIn silentSignIn() {
        return silentSignIn;
    }

    boolean enroll() {
        return enroll;
    }
}
