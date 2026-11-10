package com.touchque;

import com.touchque.internal.SdkLog;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Locale;

/**
 * Settings of a {@link TouchQueClient}. Anything left null falls back to the environment:
 * {@code TQ_API_KEY}, {@code TQ_API_SECRET} and {@code TQ_API_URL} (default
 * {@code https://api.touchque.com}).
 *
 * <pre>{@code
 * var tq = new TouchQueClient(new TouchQueOptions().apiKey("tq_...").apiSecret("..."));
 * }</pre>
 */
public final class TouchQueOptions {
    public static final String DEFAULT_BASE_URL = "https://api.touchque.com";

    private String apiKey;
    private String apiSecret;
    private String baseUrl;
    private Duration timeout = Duration.ofSeconds(10);
    private HttpClient httpClient;
    private System.Logger logger;
    private boolean debug;

    /** Your API key from the dashboard ({@code tq_…}). */
    public TouchQueOptions apiKey(String value) {
        this.apiKey = value;
        return this;
    }

    /** Your API secret. Signs every request and verifies webhooks; never send it to a browser or an app. */
    public TouchQueOptions apiSecret(String value) {
        this.apiSecret = value;
        return this;
    }

    /** The API's address. Plain http is accepted only for localhost. */
    public TouchQueOptions baseUrl(String value) {
        this.baseUrl = value;
        return this;
    }

    /** Timeout of one HTTP request (default 10 seconds). */
    public TouchQueOptions timeout(Duration value) {
        this.timeout = value;
        return this;
    }

    /**
     * Your own HttpClient. Configure it NOT to follow redirects
     * ({@code HttpClient.Redirect.NEVER}): a redirect could replay the signed headers to another host.
     */
    public TouchQueOptions httpClient(HttpClient value) {
        this.httpClient = value;
        return this;
    }

    /**
     * Where the SDK reports its own problems: a misconfigured guard, an onChallenge that threw, a
     * relay error or a relay without getLoginUser, a silent sign-in check that failed. Default:
     * nothing is logged. Lines carry an error's class, code and message, never the error object, a
     * request or a user.
     */
    public TouchQueOptions logger(System.Logger value) {
        this.logger = value;
        return this;
    }

    /** With no {@link #logger}: write those lines to System.Logger {@code "touchque"} (local development). */
    public TouchQueOptions debug(boolean value) {
        this.debug = value;
        return this;
    }

    public String apiKey() {
        return apiKey;
    }

    public String apiSecret() {
        return apiSecret;
    }

    public String baseUrl() {
        return baseUrl;
    }

    public Duration timeout() {
        return timeout;
    }

    public HttpClient httpClient() {
        return httpClient;
    }

    public System.Logger logger() {
        return logger;
    }

    public boolean debug() {
        return debug;
    }

    record Resolved(String apiKey, String apiSecret, String baseUrl, Duration timeout, HttpClient httpClient, SdkLog log) {
    }

    /** The options with the environment filled in, checked. */
    Resolved resolve() {
        String key = apiKey != null ? apiKey : System.getenv("TQ_API_KEY");
        String secret = apiSecret != null ? apiSecret : System.getenv("TQ_API_SECRET");
        String url = baseUrl != null ? baseUrl : System.getenv("TQ_API_URL");
        if (url == null || url.isEmpty()) url = DEFAULT_BASE_URL;
        if (key == null || key.isEmpty() || secret == null || secret.isEmpty()) {
            throw new TouchQueConfigException("Set TQ_API_KEY and TQ_API_SECRET (or apiKey and apiSecret in TouchQueOptions).");
        }
        if (!key.startsWith("tq_")) {
            throw new TouchQueConfigException("apiKey must start with \"tq_\". Did you accidentally swap apiKey and apiSecret?");
        }
        assertSafeBaseUrl(url, "baseUrl");
        return new Resolved(key, secret, url.replaceAll("/+$", ""), timeout, httpClient, new SdkLog(logger, debug));
    }

    /** Allow plaintext http only for localhost / loopback (local development). */
    public static void assertSafeBaseUrl(String url, String name) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new TouchQueConfigException(name + " is not a valid URL: " + url);
        }
        String scheme = uri.getScheme();
        if (scheme == null || uri.getHost() == null) throw new TouchQueConfigException(name + " is not a valid URL: " + url);
        if (scheme.equalsIgnoreCase("https")) return;
        if (scheme.equalsIgnoreCase("http")) {
            if (isLoopback(uri.getHost())) return;
            throw new TouchQueConfigException("Refusing a plaintext http:// " + name + " for \"" + uri.getHost()
                    + "\". The API key and request signature would be sent in the clear: use https://.");
        }
        throw new TouchQueConfigException(name + " must be http(s): " + url);
    }

    public static boolean isLoopback(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        return h.equals("localhost") || h.equals("127.0.0.1") || h.equals("::1") || h.equals("[::1]");
    }
}
