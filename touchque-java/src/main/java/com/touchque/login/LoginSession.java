package com.touchque.login;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchQueConfigException;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypted cookies for apps that use TouchQue Login without a session store: the sign-in in
 * progress (state, nonce, PKCE verifier, where to go back) and the signed-in session (user
 * claims, tokens). AES-256-GCM with a key derived from your secret; values too big for one
 * cookie are split across several (name.0, name.1…). The same format as the Node SDK's
 * sealSession and the Ruby gem, so they can read each other's cookies.
 */
public final class LoginSession {
    static final int CHUNK = 3800;
    static final int MAX_CHUNKS = 5;

    private LoginSession() {
    }

    private static byte[] keyOf(String secret, String purpose) {
        if (secret == null || secret.length() < 32) throw new TouchQueConfigException("The cookie secret must be at least 32 characters");
        return Crypto.sha256("touchque-login:" + purpose + ":" + secret);
    }

    /** {@code value} sealed for {@code maxAgeSeconds}: base64url of iv (12) ‖ tag (16) ‖ ciphertext. */
    public static String seal(Object value, String secret, String purpose, long maxAgeSeconds) {
        ObjectNode body = Json.object();
        body.set("v", Json.toNode(value));
        body.put("exp", Instant.now().getEpochSecond() + maxAgeSeconds);
        try {
            byte[] iv = Crypto.randomBytes(12);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyOf(secret, purpose), "AES"), new GCMParameterSpec(128, iv));
            byte[] out = cipher.doFinal(Json.write(body).getBytes(StandardCharsets.UTF_8));
            // The JDK appends the tag; the shared format puts it before the ciphertext.
            int n = out.length - 16;
            byte[] raw = new byte[12 + out.length];
            System.arraycopy(iv, 0, raw, 0, 12);
            System.arraycopy(out, n, raw, 12, 16);
            System.arraycopy(out, 0, raw, 28, n);
            return Base64Url.encode(raw);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The value, or null when it is missing, tampered with or expired. */
    public static JsonNode unseal(String sealed, String secret, String purpose) {
        if (sealed == null || sealed.isEmpty()) return null;
        byte[] key = keyOf(secret, purpose);
        byte[] raw = Base64Url.tryDecode(sealed);
        if (raw == null || raw.length < 28) return null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, raw, 0, 12));
            byte[] input = new byte[raw.length - 12];
            System.arraycopy(raw, 28, input, 0, raw.length - 28);
            System.arraycopy(raw, 12, input, raw.length - 28, 16);
            JsonNode body = Json.parse(new String(cipher.doFinal(input), StandardCharsets.UTF_8));
            JsonNode exp = body == null ? null : body.get("exp");
            if (exp == null || !exp.isNumber() || exp.doubleValue() < Instant.now().getEpochSecond()) return null;
            return body.get("v");
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    /**
     * Cookie name → value pairs storing {@code sealed} under {@code name} (split when long); null
     * values delete. {@code existing}: the names of the cookies the browser sent.
     */
    public static Map<String, String> cookieValues(String name, String sealed, Collection<String> existing) {
        Map<String, String> out = new LinkedHashMap<>();
        if (sealed == null) {
            for (String k : existing) {
                if (k.equals(name) || k.startsWith(name + ".")) out.put(k, null);
            }
            return out;
        }
        if (sealed.length() <= CHUNK) {
            out.put(name, sealed);
        } else {
            int chunks = (sealed.length() + CHUNK - 1) / CHUNK;
            if (chunks > MAX_CHUNKS) throw new TouchQueConfigException("The session is too large for cookies");
            for (int i = 0; i < chunks; i++) out.put(name + "." + i, sealed.substring(i * CHUNK, Math.min(sealed.length(), (i + 1) * CHUNK)));
        }
        for (String k : existing) {
            if ((k.equals(name) || k.startsWith(name + ".")) && !out.containsKey(k)) out.put(k, null);
        }
        return out;
    }

    /** The sealed value stored under {@code name}, joined back from its chunks. */
    public static String read(String name, Map<String, String> cookies) {
        String whole = cookies.get(name);
        if (whole != null && !whole.isEmpty()) return whole;
        StringBuilder joined = new StringBuilder();
        for (int i = 0; i < MAX_CHUNKS; i++) {
            String part = cookies.get(name + "." + i);
            if (part == null || part.isEmpty()) break;
            joined.append(part);
        }
        return joined.length() == 0 ? null : joined.toString();
    }

    /** A path inside this app to return to after sign-in (never another site). */
    public static String safeReturnTo(String value, String fallback) {
        if (value == null || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\") || value.length() > 2000) return fallback;
        return value;
    }
}
