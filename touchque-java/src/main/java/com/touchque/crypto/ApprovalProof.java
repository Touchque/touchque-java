package com.touchque.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.touchque.LoginDetail;
import com.touchque.internal.Json;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Verifies the device-signed proof of an approval ("what you see is what you sign"). When the phone
 * holds a hardware key (Secure Enclave / Android Keystore), every approval is signed over the request
 * id, the action type, the number-match code and a digest of the details the user was shown. The
 * proof arrives in the SUCCESS webhook ({@code approvalProof}) and in the consumed approval.
 * Verifying it does not require trusting Touchque.
 */
public final class ApprovalProof {
    private static final String MESSAGE_PREFIX = "touchque-approve:v2";

    private ApprovalProof() {
    }

    /** What {@link #verify} checks the proof against. */
    public static final class Options {
        private final String requestId;
        private final String type;
        private List<LoginDetail> details;
        private String challengeCode;
        private String expectedPublicKey;
        private boolean allowUnpinnedKey;

        /** @param requestId the id the request returned; @param type the action type you sent, e.g. WITHDRAW */
        public Options(String requestId, String type) {
            this.requestId = requestId;
            this.type = type;
        }

        /** The details you sent, exactly as you sent them. */
        public Options details(List<LoginDetail> v) {
            this.details = v;
            return this;
        }

        /** The number-match code, when used. */
        public Options challengeCode(String v) {
            this.challengeCode = v;
            return this;
        }

        /**
         * Pin the device: the base64 public key you stored for this user (e.g. the {@code publicKey} of
         * their first verified approval). Required unless {@link #allowUnpinnedKey} is true.
         */
        public Options expectedPublicKey(String v) {
            this.expectedPublicKey = v;
            return this;
        }

        /** Accept whatever key the proof carries (trust on first use only: store the key, pin it after). */
        public Options allowUnpinnedKey(boolean v) {
            this.allowUnpinnedKey = v;
            return this;
        }
    }

    /** True only if the proof was signed by the device key over exactly what you expect. Never throws. */
    public static boolean verify(JsonNode proof, Options o) {
        try {
            if (proof == null || !"v2".equals(Json.str(proof, "version")) || !"ECDSA-P256-SHA256".equals(Json.str(proof, "algorithm"))) return false;
            String publicKey = Json.str(proof, "publicKey");
            String message = Json.str(proof, "message");
            String signature = Json.str(proof, "signature");
            if (publicKey == null || message == null || signature == null) return false;
            if (o.expectedPublicKey != null && !o.expectedPublicKey.isEmpty()) {
                if (!MessageDigest.isEqual(o.expectedPublicKey.getBytes(StandardCharsets.UTF_8), publicKey.getBytes(StandardCharsets.UTF_8))) return false;
            } else if (!o.allowUnpinnedKey) {
                return false;
            }
            String expected = String.join("\n", MESSAGE_PREFIX, nz(o.requestId), nz(o.type), nz(o.challengeCode), Details.digest(o.details));
            if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), message.getBytes(StandardCharsets.UTF_8))) return false;
            byte[] raw = Base64.getDecoder().decode(publicKey);
            if (raw.length != 65 || raw[0] != 0x04) return false;
            byte[] sig = Base64.getDecoder().decode(signature);
            if (sig.length == 0) return false;
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(Keys.ecPublic(Arrays.copyOfRange(raw, 1, 33), Arrays.copyOfRange(raw, 33, 65)));
            s.update(message.getBytes(StandardCharsets.UTF_8));
            return s.verify(sig);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
