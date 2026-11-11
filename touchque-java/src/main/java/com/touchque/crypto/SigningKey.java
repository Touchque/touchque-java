package com.touchque.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueConfigException;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Json;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/** An ES256 or EdDSA private key that signs JWS (agent assertions, DPoP proofs). Internal API. */
public final class SigningKey {
    private final PrivateKey key;
    private final String alg;
    private final ObjectNode publicJwk;

    private SigningKey(PrivateKey key, String alg, ObjectNode publicJwk) {
        this.key = key;
        this.alg = alg;
        this.publicJwk = publicJwk;
    }

    public String alg() {
        return alg;
    }

    /** kty, crv, x (and y): the public key only. */
    public ObjectNode publicJwk() {
        return publicJwk.deepCopy();
    }

    /** A fresh ES256 key (a DPoP key kept in memory). */
    public static SigningKey newEs256() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = g.generateKeyPair();
            byte[][] xy = Keys.ecPoint(kp.getPublic());
            return new SigningKey(kp.getPrivate(), "ES256", Json.object().put("kty", "EC").put("crv", "P-256").put("x", Base64Url.encode(xy[0])).put("y", Base64Url.encode(xy[1])));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A JWK (JsonNode or its JSON text) or an EC P-256 private key in PKCS#8 PEM. */
    public static SigningKey load(Object source, String who) {
        JsonNode jwk = null;
        if (source instanceof JsonNode n) jwk = n;
        else if (source instanceof String s && s.trim().startsWith("{")) jwk = Json.parse(s);
        if (jwk != null && jwk.isObject()) return fromJwk(jwk);
        if (source instanceof String pem) return fromPem(pem, who);
        throw new TouchqueConfigException(who + ": the private key must be a JWK (JsonNode or JSON) or an EC PEM");
    }

    private static SigningKey fromJwk(JsonNode jwk) {
        String dText = Json.str(jwk, "d");
        if (dText == null || dText.isEmpty()) throw new TouchqueConfigException("The agent key must be the PRIVATE key (it has no d)");
        try {
            byte[] d = Base64Url.decode(dText);
            String kty = Json.str(jwk, "kty");
            String crv = Json.str(jwk, "crv");
            if ("OKP".equals(kty) && "Ed25519".equals(crv) && d.length == 32) {
                PrivateKey priv = Keys.edPrivate(d);
                byte[] pub = derivedEdPublic(priv, jwk);
                return new SigningKey(priv, "EdDSA", Json.object().put("kty", "OKP").put("crv", "Ed25519").put("x", Base64Url.encode(pub)));
            }
            String x = Json.str(jwk, "x");
            String y = Json.str(jwk, "y");
            if ("EC".equals(kty) && "P-256".equals(crv) && x != null && y != null) {
                return new SigningKey(Keys.ecPrivate(d), "ES256", Json.object().put("kty", "EC").put("crv", "P-256").put("x", x).put("y", y));
            }
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new TouchqueConfigException("The agent key is not a valid EC P-256 or Ed25519 JWK");
        }
        throw new TouchqueConfigException("The agent key must be EC P-256 or Ed25519");
    }

    /** The public half of an Ed25519 private key: the JDK's generator, fed the private key as its seed. */
    private static byte[] derivedEdPublic(PrivateKey priv, JsonNode jwk) throws GeneralSecurityException {
        byte[] seed = Keys.edRaw(priv);
        KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
        g.initialize(255, new java.security.SecureRandom() {
            private static final long serialVersionUID = 1L;

            @Override
            public void nextBytes(byte[] bytes) {
                System.arraycopy(seed, 0, bytes, 0, Math.min(seed.length, bytes.length));
            }
        });
        byte[] pub = Keys.edRaw(g.generateKeyPair().getPublic());
        String x = Json.str(jwk, "x");
        if (x != null && !java.util.Arrays.equals(Base64Url.decode(x), pub)) throw new GeneralSecurityException("x does not match d");
        return pub;
    }

    private static SigningKey fromPem(String pem, String who) {
        String body = pem.replaceAll("-----BEGIN [A-Z ]+-----", "").replaceAll("-----END [A-Z ]+-----", "").replaceAll("\\s", "");
        if (!pem.contains("BEGIN PRIVATE KEY")) {
            throw new TouchqueConfigException(who + ": an EC key must be PKCS#8 PEM (BEGIN PRIVATE KEY); convert with openssl pkcs8 -topk8 -nocrypt");
        }
        try {
            PrivateKey priv = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
            ECPrivateKey ec = (ECPrivateKey) priv;
            if (ec.getParams().getCurve().getField().getFieldSize() != 256 || !ec.getParams().getCurve().equals(Keys.P256.getCurve())) {
                throw new TouchqueConfigException("An EC agent key must be on P-256");
            }
            // The public point: d·G.
            ECPoint w = multiplyG(ec.getS());
            KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, Keys.P256));
            return new SigningKey(priv, "ES256", Json.object().put("kty", "EC").put("crv", "P-256")
                    .put("x", Base64Url.encode(Keys.pad32(w.getAffineX().toByteArray())))
                    .put("y", Base64Url.encode(Keys.pad32(w.getAffineY().toByteArray()))));
        } catch (GeneralSecurityException | IllegalArgumentException | ClassCastException e) {
            throw new TouchqueConfigException(who + ": the private key must be a JWK (JsonNode or JSON) or an EC P-256 PEM");
        }
    }

    /** d·G on P-256 (affine double-and-add; only used once when a PEM key is loaded). */
    private static ECPoint multiplyG(java.math.BigInteger d) {
        java.math.BigInteger p = ((java.security.spec.ECFieldFp) Keys.P256.getCurve().getField()).getP();
        java.math.BigInteger a = Keys.P256.getCurve().getA();
        ECPoint result = ECPoint.POINT_INFINITY;
        ECPoint addend = Keys.P256.getGenerator();
        for (int i = 0; i < d.bitLength(); i++) {
            if (d.testBit(i)) result = add(result, addend, p, a);
            addend = add(addend, addend, p, a);
        }
        return result;
    }

    private static ECPoint add(ECPoint s, ECPoint t, java.math.BigInteger p, java.math.BigInteger a) {
        if (s.equals(ECPoint.POINT_INFINITY)) return t;
        if (t.equals(ECPoint.POINT_INFINITY)) return s;
        java.math.BigInteger lambda;
        if (s.equals(t)) {
            if (s.getAffineY().signum() == 0) return ECPoint.POINT_INFINITY;
            lambda = s.getAffineX().pow(2).multiply(java.math.BigInteger.valueOf(3)).add(a)
                    .multiply(s.getAffineY().shiftLeft(1).modInverse(p)).mod(p);
        } else {
            if (s.getAffineX().equals(t.getAffineX())) return ECPoint.POINT_INFINITY;
            lambda = t.getAffineY().subtract(s.getAffineY()).multiply(t.getAffineX().subtract(s.getAffineX()).modInverse(p)).mod(p);
        }
        java.math.BigInteger x = lambda.pow(2).subtract(s.getAffineX()).subtract(t.getAffineX()).mod(p);
        java.math.BigInteger y = lambda.multiply(s.getAffineX().subtract(x)).subtract(s.getAffineY()).mod(p);
        return new ECPoint(x, y);
    }

    public byte[] sign(byte[] input) {
        try {
            Signature s = Signature.getInstance(alg.equals("ES256") ? "SHA256withECDSAinP1363Format" : "Ed25519");
            s.initSign(key);
            s.update(input);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A compact JWS: {@code alg} is added to the header. */
    public String jws(ObjectNode header, ObjectNode payload) {
        header.put("alg", alg);
        String input = Base64Url.encode(Json.write(header)) + "." + Base64Url.encode(Json.write(payload));
        return input + "." + Base64Url.encode(sign(input.getBytes(StandardCharsets.US_ASCII)));
    }
}
