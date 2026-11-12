package com.touchque.flow;

import com.touchque.LoginDetail;
import java.util.List;
import java.util.Map;

/** What to start an approval for. */
public final class StartOptions {
    final String user;
    List<LoginDetail> details;
    String referenceId;
    String ip;
    String userAgent;
    String browserProof;
    Map<String, Object> context;
    boolean enroll = true;

    /** @param user the user in YOUR system */
    public StartOptions(String user) {
        this.user = user;
    }

    public StartOptions details(List<LoginDetail> v) {
        this.details = v;
        return this;
    }

    public StartOptions referenceId(String v) {
        this.referenceId = v;
        return this;
    }

    /** The end user's IP. */
    public StartOptions ip(String v) {
        this.ip = v;
        return this;
    }

    public StartOptions userAgent(String v) {
        this.userAgent = v;
        return this;
    }

    /** Silent sign-ins: the {@code X-Touchque-Browser} header, passed through untouched. */
    public StartOptions browserProof(String v) {
        this.browserProof = v;
        return this;
    }

    /** For your Touchque Actions only ({@code event.context}). */
    public StartOptions context(Map<String, Object> v) {
        this.context = v;
        return this;
    }

    /**
     * False: never show the first-time linking QR (a typed username proves nothing). A user with no
     * phone then gets {@code enroll} with reason {@code enrollment_off}.
     */
    public StartOptions enroll(boolean v) {
        this.enroll = v;
        return this;
    }
}
