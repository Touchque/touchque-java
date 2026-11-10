package com.touchque.internal;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** base64url without padding. Internal API. */
public final class Base64Url {
    private Base64Url() {
    }

    public static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String encode(String text) {
        return encode(text.getBytes(StandardCharsets.UTF_8));
    }

    /** Strict decode: base64url characters only, no padding. Throws IllegalArgumentException. */
    public static byte[] decode(String text) {
        if (text == null || !text.matches("[A-Za-z0-9_-]*") || text.length() % 4 == 1) {
            throw new IllegalArgumentException("Malformed base64url");
        }
        return Base64.getUrlDecoder().decode(text);
    }

    /** The decoded bytes, or null when malformed. */
    public static byte[] tryDecode(String text) {
        try {
            return decode(text);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
