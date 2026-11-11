package com.touchque.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueConfigException;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Crypto;
import com.touchque.internal.Json;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;

/** Key helpers for AI agents ({@link com.touchque.agents.TouchqueAgent}): new key pairs and RFC 7638 thumbprints. */
public final class AgentKeys {
    private AgentKeys() {
    }

    /** A new key pair for an AI agent: register {@code publicJwk}; keep {@code privateJwk} where the agent runs. */
    public record Pair(ObjectNode privateJwk, ObjectNode publicJwk) {
    }

    /** A new key pair: ES256 (P-256) or EdDSA (Ed25519). The kid is the RFC 7638 thumbprint. */
    public static Pair generate(String alg) {
        ObjectNode pub;
        String d;
        try {
            if ("EdDSA".equals(alg)) {
                KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
                pub = Json.object().put("kty", "OKP").put("crv", "Ed25519").put("x", Base64Url.encode(Keys.edRaw(kp.getPublic())));
                d = Base64Url.encode(Keys.edRaw(kp.getPrivate()));
            } else if ("ES256".equals(alg)) {
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
                g.initialize(new ECGenParameterSpec("secp256r1"));
                KeyPair kp = g.generateKeyPair();
                byte[][] xy = Keys.ecPoint(kp.getPublic());
                pub = Json.object().put("kty", "EC").put("crv", "P-256").put("x", Base64Url.encode(xy[0])).put("y", Base64Url.encode(xy[1]));
                BigInteger s = ((ECPrivateKey) kp.getPrivate()).getS();
                d = Base64Url.encode(Keys.pad32(s.toByteArray()));
            } else {
                throw new TouchqueConfigException("alg must be ES256 or EdDSA");
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        String kid = thumbprint(pub);
        ObjectNode privateJwk = pub.deepCopy().put("d", d).put("kid", kid).put("alg", alg);
        ObjectNode publicJwk = pub.deepCopy().put("kid", kid).put("alg", alg);
        return new Pair(privateJwk, publicJwk);
    }

    /** A new ES256 key pair. */
    public static Pair generate() {
        return generate("ES256");
    }

    /** RFC 7638 thumbprint of a P-256 or Ed25519 public key (the default kid). */
    public static String thumbprint(JsonNode jwk) {
        String kty = Json.str(jwk, "kty") != null ? Json.str(jwk, "kty") : "";
        String crv = Json.str(jwk, "crv") != null ? Json.str(jwk, "crv") : "";
        String x = Json.str(jwk, "x") != null ? Json.str(jwk, "x") : "";
        String canonical = kty.equals("EC")
                ? "{\"crv\":" + Json.jsString(crv) + ",\"kty\":\"EC\",\"x\":" + Json.jsString(x) + ",\"y\":" + Json.jsString(Json.str(jwk, "y") != null ? Json.str(jwk, "y") : "") + "}"
                : "{\"crv\":" + Json.jsString(crv) + ",\"kty\":" + Json.jsString(kty) + ",\"x\":" + Json.jsString(x) + "}";
        return Base64Url.encode(Crypto.sha256(canonical));
    }

    /** base64url SHA-256 of an access token, as a DPoP proof carries it ({@code ath}). */
    public static String accessTokenHash(String accessToken) {
        return Base64Url.encode(Crypto.sha256(accessToken));
    }
}
