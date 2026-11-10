package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Json;
import java.util.ArrayList;
import java.util.List;

/**
 * A raw Safe transaction for Safe Guard: the fields the owners sign (Safe v1.3+ EIP-712 {@code SafeTx}),
 * where it runs, and what the phone needs to decode it like the guard. Integers are decimal strings
 * (null = 0); {@code data} is 0x hex (null = {@code 0x}); {@code gasToken} and {@code refundReceiver}
 * default to the zero address.
 * <pre>{@code
 * SafeTx tx = new SafeTx("1", safe, guard).to(to).value("0").data(data).operation(0).nonce("42")
 *     .config(2, 3, 172800, 259200).batchTarget(multiSendCallOnly).approverIndex(0);
 * }</pre>
 */
public final class SafeTx {
    /** An entry of the guard's address book: the phone names the address with its label. */
    public record Recipient(String address, String label) {
    }

    private final String chainId;
    private final String safe;
    private final String guard;
    private String to;
    private String value;
    private String data;
    private int operation;
    private String safeTxGas;
    private String baseGas;
    private String gasPrice;
    private String gasToken;
    private String refundReceiver;
    private String nonce;
    private Integer threshold;
    private Integer govThreshold;
    private Long govDelay;
    private Long exitDelay;
    private Boolean recipientLock;
    private final List<String> batchTargets = new ArrayList<>();
    private final List<Recipient> recipients = new ArrayList<>();
    private int approverIndex;
    private String locale;

    /**
     * @param chainId the chain id, a decimal string
     * @param safe the Safe's address
     * @param guard the TouchQueSafeGuard installed on it
     */
    public SafeTx(String chainId, String safe, String guard) {
        this.chainId = chainId;
        this.safe = safe;
        this.guard = guard;
    }

    /** The same shape as the API's {@code safeTx}: {@code chainId, safe, guard, tx: {...}, config, batchTargets, recipients, approverIndex, locale}. */
    public static SafeTx fromJson(JsonNode node) {
        JsonNode tx = node.path("tx");
        SafeTx t = new SafeTx(text(node, "chainId"), text(node, "safe"), text(node, "guard"))
                .to(text(tx, "to")).value(text(tx, "value")).data(text(tx, "data")).operation(tx.path("operation").asInt(0))
                .safeTxGas(text(tx, "safeTxGas")).baseGas(text(tx, "baseGas")).gasPrice(text(tx, "gasPrice"))
                .gasToken(text(tx, "gasToken")).refundReceiver(text(tx, "refundReceiver")).nonce(text(tx, "nonce"))
                .approverIndex(node.path("approverIndex").asInt(0)).locale(text(node, "locale"));
        JsonNode c = node.path("config");
        if (c.isObject()) {
            t.config(c.path("threshold").asInt(), c.path("govThreshold").asInt(), c.path("govDelay").asLong(), c.path("exitDelay").asLong());
            if (c.has("recipientLock")) t.recipientLock(c.path("recipientLock").asBoolean());
        }
        node.path("batchTargets").forEach(b -> t.batchTarget(b.asText()));
        node.path("recipients").forEach(r -> t.recipient(text(r, "address"), text(r, "label")));
        return t;
    }

    private static String text(JsonNode node, String key) {
        JsonNode v = node.get(key);
        return v == null || v.isNull() ? null : v.asText();
    }

    public SafeTx to(String v) {
        this.to = v;
        return this;
    }

    public SafeTx value(String v) {
        this.value = v;
        return this;
    }

    public SafeTx data(String v) {
        this.data = v;
        return this;
    }

    /** 0 call, 1 delegatecall. */
    public SafeTx operation(int v) {
        this.operation = v;
        return this;
    }

    public SafeTx safeTxGas(String v) {
        this.safeTxGas = v;
        return this;
    }

    public SafeTx baseGas(String v) {
        this.baseGas = v;
        return this;
    }

    public SafeTx gasPrice(String v) {
        this.gasPrice = v;
        return this;
    }

    public SafeTx gasToken(String v) {
        this.gasToken = v;
        return this;
    }

    public SafeTx refundReceiver(String v) {
        this.refundReceiver = v;
        return this;
    }

    public SafeTx nonce(String v) {
        this.nonce = v;
        return this;
    }

    /** The guard's settings for this Safe, as you read them from chain (delays in seconds). */
    public SafeTx config(int threshold, int govThreshold, long govDelay, long exitDelay) {
        this.threshold = threshold;
        this.govThreshold = govThreshold;
        this.govDelay = govDelay;
        this.exitDelay = exitDelay;
        return this;
    }

    /** With the address lock on, a payment or allowance outside the address book is a governance change. */
    public SafeTx recipientLock(boolean v) {
        this.recipientLock = v;
        return this;
    }

    /** A MultiSendCallOnly contract the guard opens call by call (at most 5). */
    public SafeTx batchTarget(String address) {
        this.batchTargets.add(address);
        return this;
    }

    /** An address book entry (label at most 64 bytes, without control, bidi or invisible characters). */
    public SafeTx recipient(String address, String label) {
        this.recipients.add(new Recipient(address, label));
        return this;
    }

    /** This approver's index in the guard: the approval names it. */
    public SafeTx approverIndex(int v) {
        this.approverIndex = v;
        return this;
    }

    /** The language of the rows on the phone: {@code tr} (the default) or {@code en}. */
    public SafeTx locale(String v) {
        this.locale = v;
        return this;
    }

    public String chainId() {
        return chainId;
    }

    public String safe() {
        return safe;
    }

    public String guard() {
        return guard;
    }

    public String to() {
        return to;
    }

    public String value() {
        return value;
    }

    public String data() {
        return data;
    }

    public int operation() {
        return operation;
    }

    public String safeTxGas() {
        return safeTxGas;
    }

    public String baseGas() {
        return baseGas;
    }

    public String gasPrice() {
        return gasPrice;
    }

    public String gasToken() {
        return gasToken;
    }

    public String refundReceiver() {
        return refundReceiver;
    }

    public String nonce() {
        return nonce;
    }

    public int approverIndex() {
        return approverIndex;
    }

    /** The API's {@code safeTx}. */
    public ObjectNode toJson() {
        ObjectNode tx = Json.object();
        Json.put(tx, "to", to);
        Json.put(tx, "value", value);
        Json.put(tx, "data", data);
        tx.put("operation", operation);
        Json.put(tx, "safeTxGas", safeTxGas);
        Json.put(tx, "baseGas", baseGas);
        Json.put(tx, "gasPrice", gasPrice);
        Json.put(tx, "gasToken", gasToken);
        Json.put(tx, "refundReceiver", refundReceiver);
        Json.put(tx, "nonce", nonce);
        ObjectNode out = Json.object();
        Json.put(out, "chainId", chainId);
        Json.put(out, "safe", safe);
        Json.put(out, "guard", guard);
        out.set("tx", tx);
        if (threshold != null) {
            ObjectNode c = Json.object().put("threshold", threshold).put("govThreshold", govThreshold).put("govDelay", govDelay).put("exitDelay", exitDelay);
            Json.put(c, "recipientLock", recipientLock);
            out.set("config", c);
        }
        if (!batchTargets.isEmpty()) {
            ArrayNode b = out.putArray("batchTargets");
            batchTargets.forEach(b::add);
        }
        if (!recipients.isEmpty()) {
            ArrayNode r = out.putArray("recipients");
            recipients.forEach(e -> {
                ObjectNode o = r.addObject().put("address", e.address());
                Json.put(o, "label", e.label());
            });
        }
        out.put("approverIndex", approverIndex);
        Json.put(out, "locale", locale);
        return out;
    }
}
