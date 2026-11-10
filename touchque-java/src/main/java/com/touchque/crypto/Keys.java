package com.touchque.crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/** Raw key material to JCA keys and back (P-256, Ed25519, RSA). Internal API. */
public final class Keys {
    private static final byte[] ED25519_SPKI = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final byte[] ED25519_PKCS8 = HexFormat.of().parseHex("302e020100300506032b657004220420");
    static final ECParameterSpec P256;

    static {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            P256 = params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private Keys() {
    }

    public static PublicKey ecPublic(byte[] x, byte[] y) throws GeneralSecurityException {
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), P256));
    }

    public static PrivateKey ecPrivate(byte[] d) throws GeneralSecurityException {
        return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, d), P256));
    }

    /** x and y of a P-256 public key, 32 bytes each. */
    public static byte[][] ecPoint(PublicKey key) {
        ECPoint w = ((ECPublicKey) key).getW();
        return new byte[][] {pad32(w.getAffineX().toByteArray()), pad32(w.getAffineY().toByteArray())};
    }

    public static PublicKey edPublic(byte[] raw) throws GeneralSecurityException {
        if (raw.length != 32) throw new GeneralSecurityException("Ed25519 public key must be 32 bytes");
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(concat(ED25519_SPKI, raw)));
    }

    public static PrivateKey edPrivate(byte[] raw) throws GeneralSecurityException {
        if (raw.length != 32) throw new GeneralSecurityException("Ed25519 private key must be 32 bytes");
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(concat(ED25519_PKCS8, raw)));
    }

    /** The raw 32 bytes of an Ed25519 key (the end of its DER encoding). */
    public static byte[] edRaw(java.security.Key key) {
        byte[] der = key.getEncoded();
        return Arrays.copyOfRange(der, der.length - 32, der.length);
    }

    public static PublicKey rsaPublic(byte[] n, byte[] e) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(new BigInteger(1, n), new BigInteger(1, e)));
    }

    /** Big-endian unsigned to exactly 32 bytes (leading zeros added or a sign byte dropped). */
    public static byte[] pad32(byte[] b) {
        if (b.length == 32) return b;
        if (b.length > 32) return Arrays.copyOfRange(b, b.length - 32, b.length);
        byte[] o = new byte[32];
        System.arraycopy(b, 0, o, 32 - b.length, b.length);
        return o;
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
