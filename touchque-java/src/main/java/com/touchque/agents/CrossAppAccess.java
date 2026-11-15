package com.touchque.agents;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueConfigException;
import com.touchque.TouchqueIdJagException;
import com.touchque.TouchqueNetworkException;
import com.touchque.TouchqueOptions;
import com.touchque.crypto.AgentKeys;
import com.touchque.crypto.Jws;
import com.touchque.crypto.SigningKey;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

/**
 * Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
 * draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An organization's identity
 * provider (Touchque SSO) decides which of its apps may reach which other service for its
 * members; the app trades a member's ID token for an ID-JAG there, then the ID-JAG for an access
 * token at the other service's authorization server, with no consent screen per member. Your own
 * authorization server takes them with {@link IdJagVerifier}.
 *
 * <pre>{@code
 * var jag = CrossAppAccess.requestIdJag(new CrossAppAccess.RequestOptions(id, secret, idToken, "https://auth.files.example")
 *     .issuer("https://sso.touchque.com"));
 * JsonNode tokens = CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions("https://auth.files.example/token", "acme", jag.assertion())
 *     .clientSecret(filesSecret));
 * }</pre>
 *
 * <p>Sender-constrained with DPoP (RFC 9449), optional: give the same key to both calls. The ID-JAG is
 * then bound to it (cnf.jkt) and is useless to anyone who copies it without the key. A token endpoint
 * that asks for a nonce (400 or 401 use_dpop_nonce with a valid DPoP-Nonce header) gets the same request
 * once more, with a new proof carrying it. Calls with the DPoP-bound access token carry a proof of their own:
 *
 * <pre>{@code
 * var dpopKey = CrossAppAccess.createIdJagDpopKey();
 * var jag = CrossAppAccess.requestIdJag(requestOptions.dpopKey(dpopKey));            // jag.dpopBound()
 * JsonNode tokens = CrossAppAccess.redeemIdJag(redeemOptions.dpopKey(dpopKey));
 * String at = tokens.get("access_token").asText();
 * HttpRequest call = HttpRequest.newBuilder(URI.create(url)).GET()
 *     .header("Authorization", "DPoP " + at)
 *     .header("DPoP", CrossAppAccess.idJagDpopProof(dpopKey, "GET", url, at, null)).build();
 * }</pre>
 *
 * <p>Only a 2xx answer whose body is a JSON object is a token endpoint's answer. Any other status (redirects are
 * never followed) throws {@link TouchqueIdJagException} with that status and the answer's {@code error} when it is
 * an RFC 6749 error code (else {@code server_error}); a 2xx without a JSON object throws {@code invalid_response};
 * a token endpoint that cannot be reached or read throws {@code temporarily_unavailable} with no status and the
 * failure as its cause. An interrupted call also restores the thread's interrupt status.
 */
public final class CrossAppAccess {
    public static final String ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag";
    public static final String ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
    public static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private static final HttpClient SHARED_CLIENT = TouchqueHttp.createClient(Duration.ofSeconds(10));
    /** JSON with nothing after its one value but whitespace: a token endpoint's body is one JSON object or none. */
    private static final ObjectReader ONE_JSON_VALUE = Json.MAPPER.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    /** The longest {@code error} taken as an error code (RFC 6749 sets no length; a longer one is server_error). */
    private static final int MAX_ERROR_CODE = 128;

    private CrossAppAccess() {
    }

    /** What {@link #requestIdJag} needs. */
    public static final class RequestOptions {
        private final String clientId;
        private final String clientSecret;
        private final String idToken;
        private final String audience;
        private String issuer;
        private String tokenEndpoint;
        private String resource;
        private String scope;
        private IdJagDpopKey dpopKey;

        /**
         * @param clientId your app at the identity provider ({@code tqapp_…} at Touchque SSO).
         * @param clientSecret its secret.
         * @param idToken the member's ID token the identity provider issued to your app.
         * @param audience the other service's authorization server (its issuer).
         */
        public RequestOptions(String clientId, String clientSecret, String idToken, String audience) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.idToken = idToken;
            this.audience = audience;
        }

        /** The identity provider's issuer (its token endpoint is discovered), or give {@link #tokenEndpoint}. */
        public RequestOptions issuer(String v) {
            this.issuer = v;
            return this;
        }

        public RequestOptions tokenEndpoint(String v) {
            this.tokenEndpoint = v;
            return this;
        }

        public RequestOptions resource(String v) {
            this.resource = v;
            return this;
        }

        public RequestOptions scope(String v) {
            this.scope = v;
            return this;
        }

        /** Binds the ID-JAG to this key (DPoP, RFC 9449); redeem it with the same key. */
        public RequestOptions dpopKey(IdJagDpopKey v) {
            this.dpopKey = v;
            return this;
        }
    }

    /** What {@link #redeemIdJag} needs. */
    public static final class RedeemOptions {
        private final String tokenEndpoint;
        private final String clientId;
        private final String assertion;
        private String clientSecret;
        private String resource;
        private String scope;
        private IdJagDpopKey dpopKey;

        public RedeemOptions(String tokenEndpoint, String clientId, String assertion) {
            this.tokenEndpoint = tokenEndpoint;
            this.clientId = clientId;
            this.assertion = assertion;
        }

        /** Without a secret the client is public: its client_id goes in the form. */
        public RedeemOptions clientSecret(String v) {
            this.clientSecret = v;
            return this;
        }

        public RedeemOptions resource(String v) {
            this.resource = v;
            return this;
        }

        public RedeemOptions scope(String v) {
            this.scope = v;
            return this;
        }

        /**
         * The key the ID-JAG is bound to: a DPoP proof goes along, and the access token is then DPoP-bound too
         * (sign each call with it: {@link CrossAppAccess#idJagDpopProof(IdJagDpopKey, String, String, String, String)}).
         */
        public RedeemOptions dpopKey(IdJagDpopKey v) {
            this.dpopKey = v;
            return this;
        }
    }

    /**
     * An ID-JAG the identity provider issued. {@code dpopBound}: with a DPoP key, whether the returned
     * ID-JAG carries that key's thumbprint (cnf.jkt), as an identity provider without DPoP support
     * ignores the proof; null without one.
     */
    public record IdJagGrant(String assertion, Integer expiresIn, String scope, Boolean dpopBound) {
        public IdJagGrant(String assertion, Integer expiresIn, String scope) {
            this(assertion, expiresIn, scope, null);
        }
    }

    /** A DPoP key (RFC 9449, P-256) that binds an ID-JAG to its holder; keep it in this process. */
    public static final class IdJagDpopKey {
        private final SigningKey key;
        private final String thumbprint;

        private IdJagDpopKey(SigningKey key) {
            this.key = key;
            this.thumbprint = AgentKeys.thumbprint(key.publicJwk());
        }

        /** kty, crv, x, y: the public key only. */
        public ObjectNode publicJwk() {
            return key.publicJwk();
        }

        /** RFC 7638 thumbprint: the ID-JAG's cnf.jkt. */
        public String thumbprint() {
            return thumbprint;
        }

        @Override
        public String toString() {
            return "IdJagDpopKey[thumbprint=" + thumbprint + "]";
        }
    }

    /** Makes a fresh DPoP key for {@link #requestIdJag} and {@link #redeemIdJag}. */
    public static IdJagDpopKey createIdJagDpopKey() {
        return new IdJagDpopKey(SigningKey.newEs256());
    }

    /** A DPoP proof for one POST to {@code url}, as {@link #requestIdJag} and {@link #redeemIdJag} send it. */
    public static String idJagDpopProof(IdJagDpopKey key, String url) {
        return idJagDpopProof(key, "POST", url, null, null);
    }

    /**
     * A DPoP proof (RFC 9449) for one request with this key; make a new one for every request.
     *
     * <p>Its {@code htu} is {@code url} with the scheme and host lowercased, the default port (80 for http, 443 for
     * https) dropped, "/" for an empty path, the path kept as given, and no user info, query or fragment. Only raw
     * non-ASCII characters in the path are percent-encoded (UTF-8, NFC), as the JDK's HttpClient sends them; dot
     * segments, percent-encoding and an IP address host stay as written.
     *
     * @param method the request's method: trimmed of ASCII whitespace (space, tab, CR, LF, VT, FF; not NUL, U+00A0 or
     *     other Unicode spaces) and sent uppercased as {@code htm}; null, empty or blank is POST. Any other character
     *     that is not an RFC 9110 token character throws {@link TouchqueConfigException}.
     * @param url an absolute http or https URL that {@link URI} parses with a host ({@link TouchqueConfigException} otherwise).
     * @param accessToken the DPoP-bound access token the request carries in {@code Authorization: DPoP <token>}
     *     (adds {@code ath}), or null (or empty) for a token endpoint.
     * @param nonce the server's {@code DPoP-Nonce} (RFC 9449 sections 8 and 9), or null (or empty) for none. It goes in
     *     as given, without a syntax check.
     */
    public static String idJagDpopProof(IdJagDpopKey key, String method, String url, String accessToken, String nonce) {
        return TouchqueAgent.dpopProof(key.key, htm(method), htu(url), accessToken == null || accessToken.isEmpty() ? null : accessToken,
                nonce == null || nonce.isEmpty() ? null : nonce);
    }

    /**
     * RFC 9449 htm: {@code method} trimmed of ASCII whitespace and uppercased, POST when empty; an HTTP method is an
     * RFC 9110 token.
     */
    static String htm(String method) {
        String m = method == null ? "" : trimAsciiWhitespace(method);
        if (m.isEmpty()) return "POST";
        for (int i = 0; i < m.length(); i++) {
            if (!tchar(m.charAt(i))) throw new TouchqueConfigException("a DPoP proof's method must be an HTTP method (RFC 9110 token characters only)");
        }
        return m.toUpperCase(Locale.ROOT);
    }

    /**
     * {@code s} without the ASCII whitespace at either end: space, tab, LF, VT, FF and CR. Unlike {@link String#strip()},
     * other Unicode spaces and the separators U+001C to U+001F stay (and then fail the token check).
     */
    private static String trimAsciiWhitespace(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && asciiWhitespace(s.charAt(start))) start++;
        while (end > start && asciiWhitespace(s.charAt(end - 1))) end--;
        return s.substring(start, end);
    }

    private static boolean asciiWhitespace(char c) {
        return c == ' ' || (c >= '\t' && c <= '\r');   // \t \n VT \f \r
    }

    /** RFC 9449 htu: {@code url} as {@code scheme://host[:port]/path} (see {@link #idJagDpopProof(IdJagDpopKey, String, String, String, String)}). */
    static String htu(String url) {
        URI u;
        try {
            u = new URI(new URI(url).toASCIIString());   // raw non-ASCII path characters percent-encoded (NFC, UTF-8), as HttpClient sends them
        } catch (URISyntaxException | NullPointerException e) {
            u = null;
        }
        String scheme = u != null && u.getScheme() != null ? u.getScheme().toLowerCase(Locale.ROOT) : "";
        int defaultPort = "https".equals(scheme) ? 443 : "http".equals(scheme) ? 80 : -1;
        if (defaultPort < 0 || u.getHost() == null || u.getPort() > 65535) throw new TouchqueConfigException("a DPoP proof needs an absolute http or https URL");
        String port = u.getPort() < 0 || u.getPort() == defaultPort ? "" : ":" + u.getPort();
        String path = u.getRawPath().isEmpty() ? "/" : u.getRawPath();
        return scheme + "://" + u.getHost().toLowerCase(Locale.ROOT) + port + path;
    }

    /** https, or http on this machine (tests). */
    static boolean safeUrl(String url) {
        try {
            URI u = URI.create(url);
            if (u.getHost() == null) return false;
            return "https".equals(u.getScheme()) || ("http".equals(u.getScheme()) && TouchqueOptions.isLoopback(u.getHost()));
        } catch (IllegalArgumentException | NullPointerException e) {
            return false;
        }
    }

    /** A JSON document by GET (never following redirects). */
    static JsonNode getJson(String url) {
        try {
            HttpResponse<InputStream> res = SHARED_CLIENT.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                    .header("Accept", "application/json").GET().build(), HttpResponse.BodyHandlers.ofInputStream());
            String text = TouchqueHttp.readLimited(res.body());
            if (res.statusCode() >= 400) throw new IllegalStateException(url + " answered " + res.statusCode());
            JsonNode parsed = Json.parse(text);
            return parsed instanceof ObjectNode ? parsed : Json.object();
        } catch (IOException e) {
            throw new IllegalStateException(e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    /** The identity provider's OpenID configuration, checked against its issuer. */
    static JsonNode discover(String issuer, Function<String, JsonNode> fetch) {
        JsonNode meta = fetch.apply(issuer.replaceAll("/+$", "") + "/.well-known/openid-configuration");
        if (!issuer.equals(Json.str(meta, "issuer"))) throw new TouchqueConfigException("the identity provider's metadata does not match its issuer");
        return meta;
    }

    /**
     * A token endpoint's answer: its body when that is one JSON object (else null), the latest valid DPoP-Nonce the
     * server sent during the call (see {@link CrossAppAccess#dpopNonce(List)}) and its WWW-Authenticate values (not
     * read here).
     */
    private record Answer(int status, ObjectNode data, String dpopNonce, List<String> challenges) {
        /**
         * RFC 9449 section 8: a 400 or 401 use_dpop_nonce with a valid nonce to use. The error is in the JSON body, or
         * for a 401 in a DPoP challenge; WWW-Authenticate is read only then.
         */
        boolean wantsNonce() {
            if (dpopNonce == null || (status != 400 && status != 401)) return false;
            return "use_dpop_nonce".equals(Json.str(data, "error")) || (status == 401 && dpopNonceChallenge(challenges));
        }
    }

    /**
     * POSTs the form; with a DPoP key, a fresh proof goes along, and a server that asks for its nonce gets the same
     * request once more with it. Only a 2xx with a JSON object is an answer: anything else throws
     * {@link TouchqueIdJagException}, which carries the latest valid DPoP-Nonce of the call.
     */
    private static Answer postForm(String url, Map<String, String> form, String basicId, String basicSecret, IdJagDpopKey dpopKey) {
        if (!safeUrl(url)) throw new TouchqueConfigException(url + " must be an https URL");
        StringBuilder body = new StringBuilder();
        form.forEach((k, v) -> {
            if (v == null) return;
            if (body.length() > 0) body.append('&');
            body.append(URLEncoder.encode(k, StandardCharsets.UTF_8)).append('=').append(URLEncoder.encode(v, StandardCharsets.UTF_8));
        });
        String authorization = null;
        if (basicId != null) {
            String raw = URLEncoder.encode(basicId, StandardCharsets.UTF_8) + ":" + URLEncoder.encode(basicSecret, StandardCharsets.UTF_8);
            authorization = "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
        }
        Answer a = send(url, body.toString(), authorization, dpopKey != null ? idJagDpopProof(dpopKey, url) : null, null);
        // The server wants its nonce in the proof: the same request once more, with a new proof carrying it; one retry only.
        if (dpopKey != null && a.wantsNonce()) {
            a = send(url, body.toString(), authorization, idJagDpopProof(dpopKey, "POST", url, null, a.dpopNonce()), a.dpopNonce());
        }
        if (a.status() < 200 || a.status() > 299) {
            // A refusal, or a redirect (never followed): the code is the body's error, never WWW-Authenticate's.
            String error = errorCode(a.data());
            String description = Json.str(a.data(), "error_description");
            throw new TouchqueIdJagException(error != null ? error : "server_error", description != null ? description : url + " answered " + a.status(),
                    a.status(), a.dpopNonce());
        }
        if (a.data() == null) {
            throw new TouchqueIdJagException("invalid_response", url + " answered " + a.status() + " without a JSON object", a.status(), a.dpopNonce());
        }
        return a;
    }

    /**
     * One POST. {@code latestNonce}: the valid DPoP-Nonce of the call's earlier answer, kept when this answer has none,
     * so every error carries the latest one the server sent. A server that cannot be reached, an answer the HTTP client
     * refuses (malformed or oversized headers) and a body that cannot be read (cut off, over 10 MB) throw
     * temporarily_unavailable with no status, that latest nonce (this answer's when its headers came with a valid one)
     * and the failure as the cause.
     */
    private static Answer send(String url, String body, String authorization, String proof, String latestNonce) {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        if (proof != null) req.header("DPoP", proof);
        if (authorization != null) req.header("Authorization", authorization);
        String nonce = latestNonce;
        try {
            HttpResponse<InputStream> res = SHARED_CLIENT.send(req.build(), HttpResponse.BodyHandlers.ofInputStream());
            String answered = dpopNonce(res.headers().allValues("DPoP-Nonce"));
            if (answered != null) nonce = answered;
            ObjectNode data = jsonObject(TouchqueHttp.readLimited(res.body()));
            return new Answer(res.statusCode(), data, nonce, res.headers().allValues("WWW-Authenticate"));
        } catch (IOException | TouchqueNetworkException e) {
            String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            throw new TouchqueIdJagException("temporarily_unavailable", url + ": " + why, null, nonce, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TouchqueIdJagException("temporarily_unavailable", url + ": interrupted", null, nonce, e);
        }
    }

    /** The body when it is one JSON object (whitespace around it aside), else null: empty, null, an array, not JSON. */
    private static ObjectNode jsonObject(String text) {
        try {
            return ONE_JSON_VALUE.readTree(text) instanceof ObjectNode o ? o : null;
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    /**
     * The answer's {@code error} when it is an RFC 6749 error code: a string of 1 to 128 characters, each
     * %x20-21 / %x23-5B / %x5D-7E (printable ASCII and space, except '"' and '\'). Else null (server_error).
     */
    static String errorCode(JsonNode data) {
        String error = Json.str(data, "error");
        if (error == null || error.isEmpty() || error.length() > MAX_ERROR_CODE) return null;
        for (int i = 0; i < error.length(); i++) {
            char c = error.charAt(i);
            if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') return null;
        }
        return error;
    }

    /**
     * An answer's DPoP-Nonce when it is one value in RFC 9449 nonce syntax (1*NQCHAR: printable ASCII except space,
     * '"' and '\'); a header repeated with the same value counts once. Missing, empty, invalid or repeated with
     * different values: null, so nothing is retried with it or handed over. One pass over the values.
     */
    static String dpopNonce(List<String> values) {
        String nonce = null;
        for (String v : values) {
            if (nonce != null && !nonce.equals(v)) return null;
            nonce = v;
        }
        if (nonce == null || nonce.isEmpty()) return null;
        for (int i = 0; i < nonce.length(); i++) {
            char c = nonce.charAt(i);
            if (c < 0x21 || c > 0x7e || c == '"' || c == '\\') return null;
        }
        return nonce;
    }

    /**
     * Whether WWW-Authenticate holds a DPoP challenge with error="use_dpop_nonce" (RFC 9449 section 9). One pass over
     * each value (RFC 9110 section 11.6.1), with no regular expression, so a long header costs no stack and linear time.
     * List elements split at commas outside quoted strings. An element that starts with a token not followed by "="
     * starts a challenge: its auth-scheme, then a token68 or its first auth-param. Any other auth-param belongs to the
     * challenge before it. A quoted-string value has its quoted-pairs undone; one that is never closed has no value.
     * A malformed element is skipped, and one where a challenge would start ends the challenge before it.
     */
    private static boolean dpopNonceChallenge(List<String> headers) {
        for (String h : headers) {
            String scheme = null;
            boolean elementStart = true;
            int i = 0;
            while (i < h.length()) {
                char c = h.charAt(i);
                if (c == ',' || c == ' ' || c == '\t') {
                    if (c == ',') elementStart = true;
                    i++;
                    continue;
                }
                boolean first = elementStart;
                elementStart = false;
                int start = i;
                i = tokenEnd(h, i);
                int next = spacesEnd(h, i);
                if (i == start) {
                    if (first) scheme = null;
                    i = elementEnd(h, i);
                } else if (next < h.length() && h.charAt(next) == '=') {
                    // An auth-param: token BWS "=" BWS ( token / quoted-string ).
                    String name = h.substring(start, i);
                    int v = spacesEnd(h, next + 1);
                    String value;
                    if (v < h.length() && h.charAt(v) == '"') {
                        StringBuilder quoted = new StringBuilder();
                        for (i = v + 1; i < h.length() && h.charAt(i) != '"'; i++) {
                            if (h.charAt(i) == '\\' && i + 1 < h.length()) i++;
                            quoted.append(h.charAt(i));
                        }
                        if (i == h.length()) break;   // no closing quote
                        value = quoted.toString();
                        i++;
                    } else {
                        i = tokenEnd(h, v);
                        value = h.substring(v, i);
                    }
                    int end = spacesEnd(h, i);
                    if (end < h.length() && h.charAt(end) != ',') {
                        i = elementEnd(h, end);
                    } else {
                        i = end;
                        if ("DPoP".equalsIgnoreCase(scheme) && "error".equalsIgnoreCase(name) && "use_dpop_nonce".equals(value)) return true;
                    }
                } else if (first && (next > i || next == h.length() || h.charAt(next) == ',')) {
                    scheme = h.substring(start, i);   // a challenge: its auth-scheme, then its params or token68
                    i = next;
                } else {
                    // After an auth-scheme, a token68 (never a scheme of its own); at an element's start, not a challenge.
                    if (first) scheme = null;
                    i = elementEnd(h, i);
                }
            }
        }
        return false;
    }

    /** An RFC 9110 token character (tchar). */
    private static boolean tchar(char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
    }

    /** The end of the HTTP token (RFC 9110 tchar) at {@code i}. */
    private static int tokenEnd(String h, int i) {
        while (i < h.length() && tchar(h.charAt(i))) i++;
        return i;
    }

    /** The end of the spaces and tabs at {@code i}. */
    private static int spacesEnd(String h, int i) {
        while (i < h.length() && (h.charAt(i) == ' ' || h.charAt(i) == '\t')) i++;
        return i;
    }

    /** The next comma outside a quoted string, from {@code i}, or the end. */
    private static int elementEnd(String h, int i) {
        boolean quoted = false;
        for (; i < h.length(); i++) {
            char c = h.charAt(i);
            if (quoted && c == '\\') i++;
            else if (c == '"') quoted = !quoted;
            else if (c == ',' && !quoted) return i;
        }
        return h.length();
    }

    /** Trades a member's ID token for an ID-JAG at the identity provider (token exchange, client_secret_basic). */
    public static IdJagGrant requestIdJag(RequestOptions o) {
        String endpoint = o.tokenEndpoint;
        if (endpoint == null || endpoint.isEmpty()) {
            if (o.issuer == null || o.issuer.isEmpty()) throw new TouchqueConfigException("requestIdJag needs issuer or tokenEndpoint");
            endpoint = Json.str(discover(o.issuer, CrossAppAccess::getJson), "token_endpoint");
            if (endpoint == null) throw new TouchqueConfigException("the identity provider names no token_endpoint");
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", TOKEN_EXCHANGE_GRANT);
        form.put("requested_token_type", ID_JAG_TOKEN_TYPE);
        form.put("subject_token", o.idToken);
        form.put("subject_token_type", ID_TOKEN_TYPE);
        form.put("audience", o.audience);
        form.put("resource", o.resource);
        form.put("scope", o.scope);
        Answer answer = postForm(endpoint, form, o.clientId, o.clientSecret, o.dpopKey);
        ObjectNode data = answer.data();
        String assertion = Json.str(data, "access_token");
        if (!ID_JAG_TOKEN_TYPE.equals(Json.str(data, "issued_token_type")) || assertion == null || assertion.isEmpty()) {
            throw new TouchqueIdJagException("invalid_response", "the identity provider did not answer with an ID-JAG", null, answer.dpopNonce());
        }
        Long expiresIn = Json.lng(data, "expires_in");
        Boolean dpopBound = null;
        if (o.dpopKey != null) {
            // An identity provider without DPoP support ignores the proof: say so instead of guessing.
            Jws.Parts parts = Jws.split(assertion);
            JsonNode cnf = parts != null ? parts.claims().get("cnf") : null;
            dpopBound = cnf != null && cnf.isObject() && o.dpopKey.thumbprint.equals(Json.str(cnf, "jkt"));
        }
        return new IdJagGrant(assertion, expiresIn == null ? null : expiresIn.intValue(), Json.str(data, "scope"), dpopBound);
    }

    /** Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer). */
    public static ObjectNode redeemIdJag(RedeemOptions o) {
        boolean isPublic = o.clientSecret == null || o.clientSecret.isEmpty();
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", JWT_BEARER_GRANT);
        form.put("assertion", o.assertion);
        form.put("resource", o.resource);
        form.put("scope", o.scope);
        form.put("client_id", isPublic ? o.clientId : null);
        return postForm(o.tokenEndpoint, form, isPublic ? null : o.clientId, isPublic ? null : o.clientSecret, o.dpopKey).data();
    }
}
