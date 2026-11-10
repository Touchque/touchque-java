package com.touchque.internal;

import com.touchque.TouchQueApiException;

/**
 * The SDK's own problems (a misconfigured guard, an onChallenge that threw, a relay error, a
 * failed silent sign-in check): to the integrator's {@link System.Logger}, to System.Logger
 * {@code "touchque"} with {@code debug}, else nowhere. A logger that throws never breaks a request.
 * Internal API.
 */
public final class SdkLog {
    /** Logs nothing (the default). */
    public static final SdkLog SILENT = new SdkLog(null, false);

    private final System.Logger logger;

    public SdkLog(System.Logger logger, boolean debug) {
        this.logger = logger != null ? logger : debug ? System.getLogger("touchque") : null;
    }

    public void warn(String message) {
        write(System.Logger.Level.WARNING, message);
    }

    public void error(String message) {
        write(System.Logger.Level.ERROR, message);
    }

    /** {@code Name (code): message} for a log line: never the error object, its request or its stack. */
    public static String describe(Throwable e) {
        if (e == null) return "unknown error";
        String code = null;
        if (e instanceof TouchQueApiException a) code = a.code() != null ? a.code() : a.error();
        return e.getClass().getSimpleName() + (code != null && !code.isEmpty() ? " (" + code + ")" : "") + ": " + e.getMessage();
    }

    private void write(System.Logger.Level level, String message) {
        if (logger == null) return;
        try {
            logger.log(level, message);
        } catch (RuntimeException ignored) {
            // a logger must never break a request
        }
    }
}
