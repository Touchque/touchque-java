package com.touchque.agents;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueAgentCardException;
import com.touchque.crypto.Jws;
import com.touchque.crypto.SigningKey;
import com.touchque.internal.Base64Url;
import com.touchque.internal.Json;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * A2A agent card signatures (A2A 1.0 §8.4): before your agent trusts another agent's card (its
 * name, URL, skills), check that whoever controls its keys signed exactly this card. Each entry
 * of {@code signatures} is a JWS (RFC 7515) over the card in RFC 8785 canonical form without
 * {@code signatures}; the protected header names alg, kid and optionally jku (where the keys
 * are). Keys come from {@link VerifyOptions#keys} or from the header's jku, but jku is only
 * followed on the card's own host (or a host in {@link VerifyOptions#trustedJkuHosts}): a card
 * that points at keys on a host of its choosing proves nothing. Signers must leave out fields at
 * their default values (A2A §8.4.1); the card is checked as received.
 *
 * <pre>{@code
 * String json = http.send(...).body();   // https://agent.example/.well-known/agent-card.json
 * AgentCard.verify(json, new AgentCard.VerifyOptions().cardUrl("https://agent.example/.well-known/agent-card.json"));
 * }</pre>
 */
public final class AgentCard {
    private static final Set<String> ALGS = Set.of("RS256", "ES256", "EdDSA");

    private AgentCard() {
    }

    /** Settings of {@link #verify}. */
    public static final class VerifyOptions {
        private String cardUrl;
        private List<JsonNode> keys;
        private List<String> trustedJkuHosts;
        private Function<String, JsonNode> fetch;

        /** Where the card was fetched from: its host is the one jku may point at. */
        public VerifyOptions cardUrl(String v) {
            this.cardUrl = v;
            return this;
        }

        /** JWKs you trust for this agent; checked before any jku. */
        public VerifyOptions keys(List<JsonNode> v) {
            this.keys = v;
            return this;
        }

        /** Other hosts a jku may point at (e.g. the publisher's key host). */
        public VerifyOptions trustedJkuHosts(List<String> v) {
            this.trustedJkuHosts = v;
            return this;
        }

        /** For tests: how JSON documents are fetched. */
        public VerifyOptions fetch(Function<String, JsonNode> v) {
            this.fetch = v;
            return this;
        }
    }

    /** The signature that verified; {@code keySource} is "keys" or "jku". */
    public record Verification(String kid, String alg, String keySource) {
    }

    /** A number as ECMAScript's Number::toString writes it (RFC 8785 §3.2.2.3). */
    public static String esNumber(double value) {
        if (Double.isNaN(value) || Double.isInfinite(value)) throw new TouchqueAgentCardException("malformed", "a number is not finite");
        if (value == 0) return "0";
        String sign = value < 0 ? "-" : "";
        // Shortest round-trip digits (Double.toString on Java 19+), rewritten in ECMAScript's layout.
        String text = Double.toString(Math.abs(value));
        int e = text.indexOf('E');
        String mantissa = e < 0 ? text : text.substring(0, e);
        int exp = e < 0 ? 0 : Integer.parseInt(text.substring(e + 1));
        int dot = mantissa.indexOf('.');
        String intPart = dot < 0 ? mantissa : mantissa.substring(0, dot);
        String digits = intPart + (dot < 0 ? "" : mantissa.substring(dot + 1));
        int n = intPart.length() + exp;
        String trimmed = digits.replaceFirst("^0+", "");
        n -= digits.length() - trimmed.length();
        digits = trimmed.replaceFirst("0+$", "");
        int k = digits.length();
        String out;
        if (k <= n && n <= 21) out = digits + "0".repeat(n - k);
        else if (0 < n && n <= 21) out = digits.substring(0, n) + "." + digits.substring(n);
        else if (-6 < n && n <= 0) out = "0." + "0".repeat(-n) + digits;
        else {
            int x = n - 1;
            out = digits.substring(0, 1) + (k > 1 ? "." + digits.substring(1) : "") + "e" + (x >= 0 ? "+" : "-") + Math.abs(x);
        }
        return sign + out;
    }

    private static void writeString(StringBuilder b, String s) {
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (ch < 0x20) b.append(String.format("\\u%04x", (int) ch));
                    else b.append(ch);
                }
            }
        }
        b.append('"');
    }

    private static void write(StringBuilder b, JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            b.append("null");
        } else if (node.isObject()) {
            List<String> keys = new ArrayList<>();
            node.fieldNames().forEachRemaining(keys::add);
            // String.compareTo orders by UTF-16 code units, as RFC 8785 asks.
            Collections.sort(keys);
            b.append('{');
            boolean first = true;
            for (String key : keys) {
                if (!first) b.append(',');
                first = false;
                writeString(b, key);
                b.append(':');
                write(b, node.get(key));
            }
            b.append('}');
        } else if (node.isArray()) {
            b.append('[');
            for (int i = 0; i < node.size(); i++) {
                if (i > 0) b.append(',');
                write(b, node.get(i));
            }
            b.append(']');
        } else if (node.isTextual()) {
            writeString(b, node.textValue());
        } else if (node.isBoolean()) {
            b.append(node.booleanValue() ? "true" : "false");
        } else if (node.isNumber()) {
            b.append(esNumber(node.doubleValue()));
        } else {
            throw new TouchqueAgentCardException("malformed", "cannot canonicalize this value");
        }
    }

    /** RFC 8785 (JSON Canonicalization Scheme): sorted keys (UTF-16 order), no whitespace, ECMAScript numbers. */
    public static String canonicalJson(JsonNode node) {
        StringBuilder b = new StringBuilder();
        write(b, node);
        return b.toString();
    }

    private static ObjectNode decode(String cardJson) {
        JsonNode parsed = Json.parse(cardJson);
        if (parsed == null) throw new TouchqueAgentCardException("malformed", "the card is not JSON");
        if (!(parsed instanceof ObjectNode o)) throw new TouchqueAgentCardException("malformed", "the card is not a JSON object");
        return o;
    }

    private static String payload(ObjectNode card) {
        ObjectNode rest = card.deepCopy();
        rest.remove("signatures");
        return Base64Url.encode(canonicalJson(rest));
    }

    private static String hostOf(String url) {
        return url != null && CrossAppAccess.safeUrl(url) ? URI.create(url).getRawAuthority() : null;
    }

    /** Checks the card's signatures (pass the raw JSON you received): the one that verified, or {@link TouchqueAgentCardException}. */
    public static Verification verify(String cardJson, VerifyOptions options) {
        VerifyOptions o = options != null ? options : new VerifyOptions();
        ObjectNode c = decode(cardJson);
        if (!(c.get("signatures") instanceof ArrayNode sigs) || sigs.isEmpty()) throw new TouchqueAgentCardException("unsigned", "the card has no signatures");
        Function<String, JsonNode> fetch = o.fetch != null ? o.fetch : CrossAppAccess::getJson;
        String cardHost = hostOf(o.cardUrl);
        String payload = payload(c);
        TouchqueAgentCardException last = new TouchqueAgentCardException("invalid_signature", "no signature verifies");
        for (JsonNode s : sigs) {
            String prot = Json.str(s, "protected");
            String sigText = Json.str(s, "signature");
            if (prot == null || prot.isEmpty() || sigText == null || sigText.isEmpty()) continue;
            byte[] headBytes = Base64Url.tryDecode(prot);
            JsonNode head = headBytes == null ? null : Json.parse(new String(headBytes, StandardCharsets.UTF_8));
            if (!(head instanceof ObjectNode)) continue;
            String alg = Json.str(head, "alg");
            String kid = Json.str(head, "kid");
            if (alg == null || !ALGS.contains(alg) || kid == null || kid.isEmpty() || head.has("crit")) continue;
            if (head.has("typ") && !"JOSE".equals(Json.str(head, "typ"))) continue;
            JsonNode jwk = null;
            if (o.keys != null) {
                for (JsonNode k : o.keys) {
                    if (kid.equals(Json.str(k, "kid"))) {
                        jwk = k;
                        break;
                    }
                }
            }
            String source = "keys";
            String jku = Json.str(head, "jku");
            if (jwk == null && jku != null) {
                String jkuHost = hostOf(jku);
                if (jkuHost == null || (!jkuHost.equals(cardHost) && (o.trustedJkuHosts == null || !o.trustedJkuHosts.contains(jkuHost)))) {
                    last = new TouchqueAgentCardException("untrusted_key", "jku " + jku + " is not on the card's host");
                    continue;
                }
                try {
                    JsonNode list = fetch.apply(jku).get("keys");
                    if (list != null && list.isArray()) {
                        for (JsonNode k : list) {
                            if (k.isObject() && kid.equals(Json.str(k, "kid"))) {
                                jwk = k;
                                break;
                            }
                        }
                    }
                } catch (RuntimeException e) {
                    last = new TouchqueAgentCardException("keys_unavailable", "the keys at " + jku + " could not be read: " + e.getMessage());
                    continue;
                }
                source = "jku";
            }
            if (jwk == null) {
                if ("invalid_signature".equals(last.error())) last = new TouchqueAgentCardException("untrusted_key", "no trusted key " + kid);
                continue;
            }
            byte[] sig = Base64Url.tryDecode(sigText);
            if (sig == null) continue;
            if (Jws.verify(alg, jwk, (prot + "." + payload).getBytes(StandardCharsets.US_ASCII), sig)) return new Verification(kid, alg, source);
            last = new TouchqueAgentCardException("invalid_signature", "the signature does not match the card");
        }
        throw last;
    }

    /**
     * Signs a card you publish: the card JSON with one more entry in {@code signatures}. The key
     * is an ES256 or EdDSA private JWK (JsonNode or its JSON) or an EC P-256 PKCS#8 PEM.
     */
    public static String sign(String cardJson, Object privateKey, String kid, String jku) {
        ObjectNode c = decode(cardJson);
        SigningKey key = SigningKey.load(privateKey, "AgentCard.sign");
        ObjectNode header = Json.object().put("alg", key.alg()).put("typ", "JOSE").put("kid", kid);
        if (jku != null) header.put("jku", jku);
        String prot = Base64Url.encode(Json.write(header));
        byte[] sig = key.sign((prot + "." + payload(c)).getBytes(StandardCharsets.US_ASCII));
        ObjectNode entry = Json.object().put("protected", prot).put("signature", Base64Url.encode(sig));
        if (c.get("signatures") instanceof ArrayNode list) list.add(entry);
        else c.set("signatures", Json.array().add(entry));
        return Json.write(c);
    }
}
