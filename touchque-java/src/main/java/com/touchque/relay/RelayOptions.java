package com.touchque.relay;

import com.touchque.LoginDetail;
import com.touchque.flow.Guard;
import java.util.List;
import java.util.function.Function;

/** Options of {@link RelayHandler}. */
public final class RelayOptions<T> {
    /** Called right before a success answer: open your session here; change the response (headers, status), the handler sets the body. */
    @FunctionalInterface
    public interface AuthenticatedCallback<T> {
        void accept(T request, RelayResponse response, RelayAuthenticated info) throws Exception;
    }

    final Function<T, String> getUserId;
    Function<T, String> getLoginUser;
    RateLimit.Options rateLimit = RateLimit.Options.defaults();
    boolean allowOfflineWithoutFirstFactor;
    String actionType = "LOGIN";
    Function<T, List<LoginDetail>> getDetails;
    AuthenticatedCallback<T> onAuthenticated;
    Guard.SilentSignIn silentSignIn;

    /** @param getUserId the signed-in user, for the routes that need one (enrollment, passkey management) */
    public RelayOptions(Function<T, String> getUserId) {
        this.getUserId = getUserId;
    }

    /**
     * The user who passed YOUR first factor (password step). STRONGLY RECOMMENDED: /login and the
     * offline routes then act for this user and ignore any username in the body (401
     * FIRST_FACTOR_REQUIRED when it returns nothing). Without it the offline routes stay off.
     */
    public RelayOptions<T> getLoginUser(Function<T, String> v) {
        this.getLoginUser = v;
        return this;
    }

    /** Rate limits of the pre-auth routes; null turns them off (rate limit in front of the relay then). */
    public RelayOptions<T> rateLimit(RateLimit.Options v) {
        this.rateLimit = v;
        return this;
    }

    /** Let the offline routes trust the body's username (no getLoginUser). */
    public RelayOptions<T> allowOfflineWithoutFirstFactor(boolean v) {
        this.allowOfflineWithoutFirstFactor = v;
        return this;
    }

    /** Action type for /login and the offline routes (default LOGIN). */
    public RelayOptions<T> actionType(String v) {
        this.actionType = v;
        return this;
    }

    /** Transaction context for the approval screen; build it from server-side state, never from the body. */
    public RelayOptions<T> getDetails(Function<T, List<LoginDetail>> v) {
        this.getDetails = v;
        return this;
    }

    /** Called right before a success answer: open your session for {@code info.externalUsername()}. */
    public RelayOptions<T> onAuthenticated(AuthenticatedCallback<T> v) {
        this.onAuthenticated = v;
        return this;
    }

    /**
     * Silent sign-ins for /login (default off): a new sign-in whose browser sent its device-bound key
     * proof (X-Touchque-Browser) first asks Touchque whether anything about it is new; if nothing is,
     * it succeeds at once with no push.
     */
    public RelayOptions<T> silentSignIn(Guard.SilentSignIn v) {
        this.silentSignIn = v;
        return this;
    }
}
