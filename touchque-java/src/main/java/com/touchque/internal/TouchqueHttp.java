package com.touchque.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueApiException;
import com.touchque.TouchqueFeatureException;
import com.touchque.TouchqueNetworkException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Every partner API call: signed with HMAC-SHA256 over
 * {@code METHOD:pathWithQuery:timestamp:nonce:sha256(body)}, sent once, never redirected.
 * Internal API.
 */
public final class TouchqueHttp {
    public static final String SDK_VERSION = "5.1.0";
    static final int MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

    private final String apiKey;
    private final String apiSecret;
    private final String baseUrl;
    private final Duration timeout;
    private final HttpClient client;
    private final SdkLog log;

    public TouchqueHttp(String apiKey, String apiSecret, String baseUrl, Duration timeout, HttpClient client) {
        this(apiKey, apiSecret, baseUrl, timeout, client, SdkLog.SILENT);
    }

    /** @param log where the SDK reports its own problems (silent unless the integrator passed a logger or debug) */
    public TouchqueHttp(String apiKey, String apiSecret, String baseUrl, Duration timeout, HttpClient client, SdkLog log) {
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
        this.baseUrl = baseUrl;
        this.timeout = timeout == null || timeout.isZero() || timeout.isNegative() ? Duration.ofSeconds(10) : timeout;
        this.client = client != null ? client : createClient(this.timeout);
        this.log = log != null ? log : SdkLog.SILENT;
    }

    /** An HttpClient that never follows redirects: a redirect could replay the signed headers to another host. */
    public static HttpClient createClient(Duration timeout) {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout == null ? Duration.ofSeconds(10) : timeout)
                .build();
    }

    public String baseUrl() {
        return baseUrl;
    }

    public String apiSecret() {
        return apiSecret;
    }

    public HttpClient client() {
        return client;
    }

    public Duration timeout() {
        return timeout;
    }

    /** Where the SDK reports its own problems (silent by default). */
    public SdkLog log() {
        return log;
    }

    public JsonNode get(String path) {
        return send("GET", path, null).json();
    }

    public JsonNode get(String path, Map<String, ?> query) {
        return send("GET", path + buildQuery(query), null).json();
    }

    public JsonNode post(String path, JsonNode body) {
        return send("POST", path, body != null ? body : Json.object()).json();
    }

    public JsonNode put(String path, JsonNode body) {
        return send("PUT", path, body != null ? body : Json.object()).json();
    }

    public JsonNode patch(String path, JsonNode body) {
        return send("PATCH", path, body != null ? body : Json.object()).json();
    }

    public JsonNode delete(String path) {
        return send("DELETE", path, null).json();
    }

    /** A signed GET whose answer is returned as text (an export file). */
    public String getText(String path) {
        return send("GET", path, null).text();
    }

    /** A JSON node read into a type (records included). */
    public static <T> T to(JsonNode node, Class<T> type) {
        if (node == null || node.isNull()) return null;
        try {
            return Json.MAPPER.treeToValue(node, type);
        } catch (JsonProcessingException e) {
            throw new TouchqueNetworkException("could not read the answer: " + e.getOriginalMessage(), e);
        }
    }

    /** Deterministic query string: keys sorted, values URL-encoded, {@code ?}-prefixed (or empty). */
    public static String buildQuery(Map<String, ?> query) {
        if (query == null) return "";
        TreeMap<String, String> sorted = new TreeMap<>();
        query.forEach((k, v) -> {
            if (v != null) sorted.put(k, String.valueOf(v));
        });
        if (sorted.isEmpty()) return "";
        StringBuilder sb = new StringBuilder("?");
        sorted.forEach((k, v) -> {
            if (sb.length() > 1) sb.append('&');
            sb.append(seg(k)).append('=').append(seg(v));
        });
        return sb.toString();
    }

    /** A path segment, URL-encoded: everything but A-Z a-z 0-9 - _ . ~ (RFC 3986 unreserved). */
    public static String seg(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(bytes.length);
        for (byte b : bytes) {
            int c = b & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
                sb.append((char) c);
            } else {
                sb.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16))).append(Character.toUpperCase(Character.forDigit(c & 15, 16)));
            }
        }
        return sb.toString();
    }

    public static String sign(String secret, String method, String pathWithQuery, String body, String timestamp, String nonce) {
        String message = method.toUpperCase(Locale.ROOT) + ":" + pathWithQuery + ":" + timestamp + ":" + nonce + ":" + Crypto.sha256Hex(body);
        return Crypto.hmacHex(secret, message);
    }

    private record Result(JsonNode json, String text) {
    }

    private Result send(String method, String pathWithQuery, JsonNode body) {
        String bodyText = body == null ? "" : Json.write(body);
        String timestamp = Long.toString(System.currentTimeMillis());
        String nonce = Crypto.randomHex(16);
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(baseUrl + pathWithQuery))
                .timeout(timeout)
                .header("x-api-key", apiKey)
                .header("x-signature", sign(apiSecret, method, pathWithQuery, bodyText, timestamp, nonce))
                .header("x-timestamp", timestamp)
                .header("x-nonce", nonce)
                .header("Accept", "application/json")
                .header("User-Agent", "touchque-java-sdk/" + SDK_VERSION);
        if (body != null) {
            request.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(bodyText, StandardCharsets.UTF_8));
        } else {
            request.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<InputStream> response;
        String text;
        try {
            response = client.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            text = readLimited(response.body());
        } catch (HttpTimeoutException e) {
            throw new TouchqueNetworkException("timed out", e);
        } catch (IOException e) {
            throw new TouchqueNetworkException(String.valueOf(e.getMessage()), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TouchqueNetworkException("interrupted", e);
        }
        int status = response.statusCode();
        JsonNode parsed = Json.parse(text);
        if (status >= 300) {
            ObjectNode data = parsed instanceof ObjectNode o ? o : Json.object();
            if (Json.integer(data, "retryAfter") == null) {
                response.headers().firstValue("Retry-After").ifPresent(v -> {
                    try {
                        data.put("retryAfter", Integer.parseInt(v.trim()));
                    } catch (NumberFormatException ignored) {
                        // an HTTP date: not a number of seconds
                    }
                });
            }
            if (status < 400) {
                // An API endpoint never redirects; one that does is not Touchque's.
                throw new TouchqueApiException(status, data, "Touchque: unexpected redirect (HTTP " + status + "); redirects are never followed.");
            }
            throw TouchqueFeatureException.of(status, data, null);
        }
        return new Result(parsed != null ? parsed : Json.object(), text);
    }

    /** The body as UTF-8 text, refusing more than 10 MB. */
    public static String readLimited(InputStream stream) throws IOException {
        try (InputStream in = stream; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[16 * 1024];
            int read;
            while ((read = in.read(chunk)) > 0) {
                if (out.size() + read > MAX_RESPONSE_BYTES) throw new TouchqueNetworkException("the answer is larger than 10 MB");
                out.write(chunk, 0, read);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }
}
