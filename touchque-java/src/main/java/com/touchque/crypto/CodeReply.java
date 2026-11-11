package com.touchque.crypto;

import com.touchque.internal.Base64Url;
import com.touchque.internal.Crypto;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A code the person types back on the phone ({@code LoginRequestOptions.reply}): a sign-in code
 * another service sent them (a text message, WhatsApp, e-mail). Each request gets a one-time P-256
 * key pair; its public key goes with the request, the phone encrypts what was typed to it, and
 * only you can open it: Touchque stores and hands back nothing but the ciphertext
 * ({@code login().status(id).reply().get("ct")}).
 *
 * <p>ECDH P-256, HKDF-SHA256 (salt: the request id, info {@code touchque-code-reply-v1}),
 * AES-256-GCM (additional data {@code touchque-code-reply:<request id>}), as
 * {@code v1.<the phone's one-time key, x9.63>.<nonce|ciphertext|tag>}, base64url.
 */
public final class CodeReply {
    private static final byte[] INFO = "touchque-code-reply-v1".getBytes(StandardCharsets.UTF_8);
    private static final Pattern CT = Pattern.compile("^v1\\.([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)$");
    private static final Pattern CODE = Pattern.compile("^[A-Za-z0-9 -]{4,20}$");

    private CodeReply() {
    }

    /**
     * A one-time key pair for one request: send {@code publicKey} (the uncompressed P-256 point,
     * base64url) as the reply's key, keep {@code privateKey} (PKCS#8 DER, base64url) server-side.
     */
    public record Key(String publicKey, String privateKey) {
        @Override
        public String toString() {
            return "CodeReply.Key[publicKey=" + publicKey + ", privateKey=***]";
        }
    }

    public static Key newKey() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = g.generateKeyPair();
            byte[][] xy = Keys.ecPoint(kp.getPublic());
            byte[] point = new byte[65];
            point[0] = 4;
            System.arraycopy(xy[0], 0, point, 1, 32);
            System.arraycopy(xy[1], 0, point, 33, 32);
            return new Key(Base64Url.encode(point), Base64Url.encode(kp.getPrivate().getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The code the person typed, or null when {@code ct} does not open with this key for this request. */
    public static String open(String privateKey, String requestId, String ct) {
        Matcher m = CT.matcher(ct == null ? "" : ct);
        if (!m.matches()) return null;
        byte[] epk = Base64Url.tryDecode(m.group(1));
        byte[] box = Base64Url.tryDecode(m.group(2));
        byte[] der = Base64Url.tryDecode(privateKey == null ? "" : privateKey);
        if (epk == null || box == null || der == null || epk.length != 65 || epk[0] != 4 || box.length < 12 + 16 + 1) return null;
        try {
            PrivateKey priv = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
            PublicKey peer = Keys.ecPublic(Arrays.copyOfRange(epk, 1, 33), Arrays.copyOfRange(epk, 33, 65));
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(priv);
            ka.doPhase(peer, true);
            byte[] key = hkdf(ka.generateSecret(), requestId.getBytes(StandardCharsets.UTF_8));
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, box, 0, 12));
            c.updateAAD(("touchque-code-reply:" + requestId).getBytes(StandardCharsets.UTF_8));
            String code = new String(c.doFinal(box, 12, box.length - 12), StandardCharsets.UTF_8).trim();
            return CODE.matcher(code).matches() ? code : null;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return null;
        }
    }

    /** HKDF-SHA256 (RFC 5869) for one 32-byte block. */
    private static byte[] hkdf(byte[] ikm, byte[] salt) {
        byte[] prk = Crypto.hmacSha256(salt, ikm);
        byte[] info = Arrays.copyOf(INFO, INFO.length + 1);
        info[INFO.length] = 1;
        return Crypto.hmacSha256(prk, info);
    }
}
