package com.touchque.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Json;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

/** JWS signature checks for the algorithms Touchque uses (ES256, RS256, EdDSA). Internal API. */
public final class Jws {
    private Jws() {
    }

    /** The parts of a compact JWS. */
    public record Parts(ObjectNode header, ObjectNode claims, byte[] input, byte[] signature) {
    }

    /** True when {@code signature} over {@code input} verifies with the JWK for {@code alg}. Never throws. */
    public static boolean verify(String alg, JsonNode jwk, byte[] input, byte[] signature) {
        try {
            String kty = Json.str(jwk, "kty");
            PublicKey key;
            String algorithm;
            if ("ES256".equals(alg) && "EC".equals(kty) && "P-256".equals(Json.str(jwk, "crv"))) {
                if (signature.length != 64) return false;
                key = Keys.ecPublic(Base64Url.decode(Json.str(jwk, "x")), Base64Url.decode(Json.str(jwk, "y")));
                algorithm = "SHA256withECDSAinP1363Format";
            } else if ("RS256".equals(alg) && "RSA".equals(kty)) {
                key = Keys.rsaPublic(Base64Url.decode(Json.str(jwk, "n")), Base64Url.decode(Json.str(jwk, "e")));
                algorithm = "SHA256withRSA";
            } else if ("EdDSA".equals(alg) && "OKP".equals(kty) && "Ed25519".equals(Json.str(jwk, "crv"))) {
                if (signature.length != 64) return false;
                key = Keys.edPublic(Base64Url.decode(Json.str(jwk, "x")));
                algorithm = "Ed25519";
            } else {
                return false;
            }
            Signature s = Signature.getInstance(algorithm);
            s.initVerify(key);
            s.update(input);
            return s.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException | NullPointerException e) {
            return false;
        }
    }

    /** Header and claims of a compact JWS, or null when it is not one. */
    public static Parts split(String token) {
        if (token == null) return null;
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) return null;
        try {
            JsonNode header = Json.parse(new String(Base64Url.decode(parts[0]), StandardCharsets.UTF_8));
            JsonNode claims = Json.parse(new String(Base64Url.decode(parts[1]), StandardCharsets.UTF_8));
            if (!(header instanceof ObjectNode h) || !(claims instanceof ObjectNode c)) return null;
            return new Parts(h, c, (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII), Base64Url.decode(parts[2]));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
