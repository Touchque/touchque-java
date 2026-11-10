package com.touchque.crypto;

import com.touchque.TouchQueConfigException;
import com.touchque.internal.Crypto;
import com.touchque.resources.SafeTx;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Safe Guard approvals, checked without trusting TouchQue. The approver's phone decodes the raw Safe
 * transaction itself and signs, with a P-256 key only its biometrics unlock, a 105-byte approval that
 * TouchQueSafeGuard checks on chain: {@code index (1) | expiresAt (8) | displayDigest (32) | r (32) | s (32)},
 * over the SHA-256 of the 149-byte message {@code "TQG1" | purpose (1) | chainId (32) | guard (20) | Safe (20)
 * | subject (32) | expiresAt (8) | displayDigest (32)}, where subject is the Safe transaction hash (EIP-712,
 * purpose 1 {@code approve}) or, for a change the guard schedules, the governance hash (purpose 2
 * {@code schedule}). {@link #verify} makes the guard's check off chain: both hashes are computed here from the
 * raw fields, so a co-signer (or your own server) refuses an approval of anything else, whoever relayed it.
 */
public final class SafeApproval {
    /** One row the phone showed, in order. */
    public record Row(String label, String value) {
    }

    /**
     * {@link #verify}'s verdict. {@code reason} is null when valid, else {@code approval_malformed},
     * {@code public_key_invalid}, {@code approver_index_mismatch}, {@code approval_expired}, {@code rows_differ},
     * {@code high_s} or {@code signature_invalid}. {@code expiresAt} is Unix seconds (unsigned).
     */
    public record Verification(boolean valid, String reason, String purpose, Integer approverIndex, Long expiresAt, String displayDigest,
            String safeTxHash, String governanceHash) {
    }

    /** Narrows what {@link #verify} accepts. */
    public static final class VerifyOptions {
        private String purpose;
        private Integer approverIndex;
        private String displayDigest;
        private List<Row> rows;
        private Instant now;

        /**
         * The purpose you expect: {@code approve} (the default) or {@code schedule}. Unset accepts only an
         * ordinary approval; a governance approval carries no Safe nonce and only starts the guard's waiting
         * time, so ask for {@code schedule} by name.
         */
        public VerifyOptions purpose(String v) {
            this.purpose = v;
            return this;
        }

        /** The approver's index in the guard: the approval must name it. */
        public VerifyOptions approverIndex(Integer v) {
            this.approverIndex = v;
            return this;
        }

        /** The digest of the rows the phone must have shown (from your own decoding). */
        public VerifyOptions displayDigest(String v) {
            this.displayDigest = v;
            return this;
        }

        /** Or the rows themselves; their digest is compared. */
        public VerifyOptions rows(List<Row> v) {
            this.rows = v;
            return this;
        }

        /** The time to check the expiry against (default: now). */
        public VerifyOptions now(Instant v) {
            this.now = v;
            return this;
        }
    }

    private static final byte[] MAGIC = "TQG1".getBytes(StandardCharsets.US_ASCII);
    // The guard (MAX_APPROVAL_TTL) refuses an approval valid for longer than a day.
    private static final long MAX_APPROVAL_TTL = 86400;
    // OpenZeppelin P256 (the guard) refuses s above N/2.
    private static final BigInteger HALF_N = new BigInteger("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", 16);
    private static final BigInteger P = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    private static final BigInteger B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    private static final BigInteger MAX_UINT256 = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
    private static final BigInteger MAX_UINT64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
    // SubjectPublicKeyInfo prefix of an uncompressed P-256 point.
    private static final byte[] SPKI_P256 = HexFormat.of().parseHex("3059301306072a8648ce3d020106082a8648ce3d030107034200");
    private static final String ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
    private static final Pattern ADDRESS = Pattern.compile("^0x[0-9a-fA-F]{40}$");
    private static final Pattern HEX = Pattern.compile("^0x([0-9a-fA-F]{2})*$");
    private static final Pattern DECIMAL = Pattern.compile("^(0|[1-9][0-9]*)$");
    private static final Pattern APPROVAL = Pattern.compile("^(0x)?[0-9a-fA-F]{210}$");
    private static final Pattern KEY = Pattern.compile("^[0-9a-fA-F]{128}$");

    // ── Keccak-256 (the Ethereum hash: Keccak padding, not SHA3-256) ──
    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L,
    };
    // Rotation of lane x + 5y.
    private static final int[] ROT = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

    private static final byte[] DOMAIN_TYPEHASH = keccak256(ascii("EIP712Domain(uint256 chainId,address verifyingContract)"));
    private static final byte[] SAFE_TX_TYPEHASH = keccak256(ascii(
            "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"));
    private static final byte[] GOVERNANCE_TYPEHASH = keccak256(ascii(
            "TouchQueGovernance(uint256 chainId,address safe,address to,uint256 value,bytes32 dataHash,uint8 operation)"));
    private static final byte[] SCHEDULE_SELECTOR = Arrays.copyOf(keccak256(ascii("schedule(address,bytes32,bytes)")), 4);

    private SafeApproval() {
    }

    /** The Safe transaction hash (EIP-712, domain = chainId + the Safe): what the owners sign and an ordinary approval covers. */
    public static String safeTxHash(SafeTx target) {
        Fields t = parse(target);
        byte[] domain = keccak256(concat(DOMAIN_TYPEHASH, t.chainId, t.safe));
        byte[] struct = keccak256(concat(SAFE_TX_TYPEHASH, t.to, t.value, keccak256(t.data), word(t.operation), t.safeTxGas, t.baseGas,
                t.gasPrice, t.gasToken, t.refundReceiver, t.nonce));
        return hex(keccak256(concat(new byte[] {0x19, 0x01}, domain, struct)));
    }

    /** What the guard schedules a governance change under: the change itself, without the nonce or gas fields. */
    public static String governanceHash(SafeTx target) {
        Fields t = parse(target);
        return hex(keccak256(concat(GOVERNANCE_TYPEHASH, t.chainId, t.safe, t.to, t.value, keccak256(t.data), word(t.operation))));
    }

    /**
     * The 149-byte message the phone signs (its SHA-256 is what the guard verifies), as 0x hex.
     *
     * @param purpose {@code approve} or {@code schedule}
     * @param chainId a decimal string
     * @param expiresAt Unix seconds (unsigned)
     */
    public static String message(String purpose, String chainId, String guard, String safe, String subject, long expiresAt, String displayDigest) {
        byte code = switch (String.valueOf(purpose)) {
            case "approve" -> 1;
            case "schedule" -> 2;
            default -> throw new TouchQueConfigException("SafeApproval: purpose is 'approve' or 'schedule'.");
        };
        byte[] expires = ByteBuffer.allocate(8).putLong(expiresAt).array();
        return hex(concat(MAGIC, new byte[] {code}, uint(chainId, "chainId", MAX_UINT64), Arrays.copyOfRange(address(guard, "guard"), 12, 32),
                Arrays.copyOfRange(address(safe, "safe"), 12, 32), bytes(subject, "subject", 32), expires, bytes(displayDigest, "displayDigest", 32)));
    }

    /** SHA-256 of the rows as "label\x1Fvalue" joined by "\x1E" (UTF-8), as 0x hex: the digest an approval carries. */
    public static String displayDigest(List<Row> rows) {
        String canonical = rows.stream().map(r -> r.label() + '\u001F' + r.value()).collect(Collectors.joining("\u001E"));
        return hex(Crypto.sha256(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Checks a phone's Safe Guard approval the way TouchQueSafeGuard does, without trusting the server that
     * relayed it: the Safe and governance hashes come from {@code target}, the key from the guard's approver list
     * on chain ({@code x || y}, 128 hex characters). Only an ordinary approval ({@code approve}) is accepted
     * unless {@link VerifyOptions#purpose} names {@code schedule}. Throws only when the target is not a Safe
     * transaction or the purpose is unknown; a refused approval is a verdict.
     * <pre>{@code
     * JsonNode status = tq.safeGuard().status(requestId);
     * SafeApproval.Verification check = SafeApproval.verify(myTx, status.path("safeTx").path("approval").asText(), approverKeyFromChain,
     *     new SafeApproval.VerifyOptions().approverIndex(0));
     * if (!check.valid()) throw new IllegalStateException("approval refused: " + check.reason());
     * }</pre>
     */
    public static Verification verify(SafeTx target, String approval, String publicKey, VerifyOptions options) {
        VerifyOptions o = options == null ? new VerifyOptions() : options;
        Fields t = parse(target);
        String safeTxHash = safeTxHash(target);
        String governanceHash = governanceHash(target);
        if (approval == null || !APPROVAL.matcher(approval).matches()) {
            return new Verification(false, "approval_malformed", null, null, null, null, safeTxHash, governanceHash);
        }
        byte[] b = HexFormat.of().parseHex(strip0x(approval));
        int index = b[0] & 0xff;
        long expiresAt = ByteBuffer.wrap(b, 1, 8).getLong();
        String digest = hex(Arrays.copyOfRange(b, 9, 41));
        java.util.function.Function<String, Verification> refuse = reason ->
                new Verification(false, reason, null, index, expiresAt, digest, safeTxHash, governanceHash);
        PublicKey key = publicKey(publicKey);
        if (key == null) return refuse.apply("public_key_invalid");
        if (o.approverIndex != null && o.approverIndex != index) return refuse.apply("approver_index_mismatch");
        long now = (o.now != null ? o.now : Instant.now()).getEpochSecond();
        if (now < 0 || Long.compareUnsigned(expiresAt, now) < 0 || Long.compareUnsigned(expiresAt, now + MAX_APPROVAL_TTL) > 0) {
            return refuse.apply("approval_expired");
        }
        String expected = o.displayDigest != null ? o.displayDigest : o.rows != null ? displayDigest(o.rows) : null;
        if (expected != null && !("0x" + strip0x(expected.toLowerCase(java.util.Locale.ROOT))).equals(digest)) return refuse.apply("rows_differ");
        if (new BigInteger(1, Arrays.copyOfRange(b, 73, 105)).compareTo(HALF_N) > 0) return refuse.apply("high_s");

        String chainId = new BigInteger(1, t.chainId).toString();
        // Never both: a schedule approval is not permission to execute, so without a purpose only approve is tried.
        String purpose = o.purpose != null ? o.purpose : "approve";
        String message = message(purpose, chainId, hex(Arrays.copyOfRange(t.guard, 12, 32)), hex(Arrays.copyOfRange(t.safe, 12, 32)),
                "approve".equals(purpose) ? safeTxHash : governanceHash, expiresAt, digest);
        try {
            Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
            verifier.initVerify(key);
            verifier.update(HexFormat.of().parseHex(message.substring(2)));
            if (verifier.verify(Arrays.copyOfRange(b, 41, 105))) {
                return new Verification(true, null, purpose, index, expiresAt, digest, safeTxHash, governanceHash);
            }
        } catch (GeneralSecurityException e) {
            // A signature the provider cannot read is not a valid one.
        }
        return refuse.apply("signature_invalid");
    }

    /**
     * The owners' Safe signatures with the approvals appended (approvals by index | count | "TQG1"): the
     * {@code signatures} argument of {@code execTransaction} for an ordinary transaction.
     */
    public static String withApprovals(String ownerSignatures, List<String> approvals) {
        List<byte[]> items = approvals(approvals);
        return hex(concat(bytes(ownerSignatures, "ownerSignatures", -1), concat(items.toArray(new byte[0][])), new byte[] {(byte) items.size()}, MAGIC));
    }

    /** The call data of {@code guard.schedule(safe, governanceHash, approvals)}, which starts a governance change's waiting time. */
    public static String scheduleCall(String safe, String governanceHash, List<String> approvals) {
        byte[] joined = concat(approvals(approvals).toArray(new byte[0][]));
        return hex(concat(SCHEDULE_SELECTOR, address(safe, "safe"), bytes(governanceHash, "governanceHash", 32), word(96),
                uint(Integer.toString(joined.length), "length", MAX_UINT256), joined, new byte[(32 - joined.length % 32) % 32]));
    }

    private static void keccakF(long[] a) {
        long[] c = new long[5];
        long[] b = new long[25];
        for (long rc : RC) {
            for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (int x = 0; x < 5; x++) {
                long d = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) a[x + y] ^= d;
            }
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = Long.rotateLeft(a[x + 5 * y], ROT[x + 5 * y]);
            }
            for (int y = 0; y < 25; y += 5) {
                for (int x = 0; x < 5; x++) a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]);
            }
            a[0] ^= rc;
        }
    }

    private static byte[] keccak256(byte[] data) {
        final int rate = 136;
        byte[] padded = Arrays.copyOf(data, data.length / rate * rate + rate);
        padded[data.length] ^= 0x01;
        padded[padded.length - 1] ^= (byte) 0x80;
        long[] a = new long[25];
        ByteBuffer in = ByteBuffer.wrap(padded).order(ByteOrder.LITTLE_ENDIAN);
        for (int off = 0; off < padded.length; off += rate) {
            for (int k = 0; k < rate / 8; k++) a[k] ^= in.getLong(off + 8 * k);
            keccakF(a);
        }
        ByteBuffer out = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN);
        for (int k = 0; k < 4; k++) out.putLong(a[k]);
        return out.array();
    }

    // ── Field parsing: the partner's own data, so a wrong field throws ──

    private record Fields(byte[] chainId, byte[] safe, byte[] guard, byte[] to, byte[] value, byte[] data, byte operation, byte[] safeTxGas,
            byte[] baseGas, byte[] gasPrice, byte[] gasToken, byte[] refundReceiver, byte[] nonce) {
    }

    private static Fields parse(SafeTx t) {
        if (t == null) throw new TouchQueConfigException("SafeApproval: pass a SafeTx.");
        if (t.operation() != 0 && t.operation() != 1) throw new TouchQueConfigException("SafeApproval: operation must be 0 (call) or 1 (delegatecall).");
        if (t.nonce() == null || t.nonce().isEmpty()) throw new TouchQueConfigException("SafeApproval: nonce is required.");
        return new Fields(uint(t.chainId(), "chainId", MAX_UINT64), address(t.safe(), "safe"), address(t.guard(), "guard"), address(t.to(), "to"),
                uint(orZero(t.value()), "value", MAX_UINT256), bytes(t.data() == null ? "0x" : t.data(), "data", -1), (byte) t.operation(),
                uint(orZero(t.safeTxGas()), "safeTxGas", MAX_UINT256), uint(orZero(t.baseGas()), "baseGas", MAX_UINT256),
                uint(orZero(t.gasPrice()), "gasPrice", MAX_UINT256), address(t.gasToken() == null ? ZERO_ADDRESS : t.gasToken(), "gasToken"),
                address(t.refundReceiver() == null ? ZERO_ADDRESS : t.refundReceiver(), "refundReceiver"), uint(t.nonce(), "nonce", MAX_UINT256));
    }

    private static String orZero(String v) {
        return v == null ? "0" : v;
    }

    private static byte[] uint(String value, String field, BigInteger max) {
        if (value == null || !DECIMAL.matcher(value).matches() || new BigInteger(value).compareTo(max) > 0) {
            throw new TouchQueConfigException("SafeApproval: " + field + " must be a non-negative integer as a decimal string.");
        }
        return word(new BigInteger(value));
    }

    private static byte[] word(long value) {
        return word(BigInteger.valueOf(value));
    }

    private static byte[] word(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - n, out, 32 - n, n);
        return out;
    }

    private static byte[] address(String value, String field) {
        if (value == null || !ADDRESS.matcher(value).matches()) throw new TouchQueConfigException("SafeApproval: " + field + " must be an address (0x and 40 hex characters).");
        return concat(new byte[12], HexFormat.of().parseHex(value.substring(2)));
    }

    private static byte[] bytes(String value, String field, int size) {
        if (value == null || !HEX.matcher(value).matches() || (size >= 0 && value.length() != 2 + 2 * size)) {
            throw new TouchQueConfigException("SafeApproval: " + field + " must be 0x-prefixed hex" + (size >= 0 ? " of " + size + " bytes." : "."));
        }
        return HexFormat.of().parseHex(value.substring(2));
    }

    private static List<byte[]> approvals(List<String> approvals) {
        if (approvals == null || approvals.isEmpty() || approvals.size() > 255) throw new TouchQueConfigException("SafeApproval: pass 1 to 255 approvals.");
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < approvals.size(); i++) {
            String a = approvals.get(i);
            out.add(bytes(a != null && !a.startsWith("0x") ? "0x" + a : a, "approvals[" + i + "]", 105));
        }
        out.sort(Comparator.comparingInt(a -> a[0] & 0xff));
        return out;
    }

    private static PublicKey publicKey(String key) {
        String xy = strip0x(key == null ? "" : key);
        if (!KEY.matcher(xy).matches()) return null;
        byte[] raw = HexFormat.of().parseHex(xy);
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(raw, 0, 32));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(raw, 32, 64));
        // On the curve: y^2 = x^3 - 3x + b (mod p).
        if (x.compareTo(P) >= 0 || y.compareTo(P) >= 0 || !y.modPow(BigInteger.TWO, P).equals(x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(B).mod(P))) {
            return null;
        }
        try {
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(concat(SPKI_P256, new byte[] {4}, raw)));
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.writeBytes(p);
        return out.toByteArray();
    }

    private static String strip0x(String s) {
        return s.startsWith("0x") ? s.substring(2) : s;
    }

    private static String hex(byte[] b) {
        return "0x" + HexFormat.of().formatHex(b);
    }
}
