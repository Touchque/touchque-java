package com.touchque.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueApprovalMismatchException;
import com.touchque.internal.Json;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * What a partner's server checks before executing what an AI agent asked for: the approval token's
 * claims match the transaction (person, action type, authorization details) and, offline, its ES256
 * signature against Touchque's keys ({@code GET /agents/jwks.json}). {@code tq.agents().redeemApproval}
 * makes a token single-use.
 */
public final class ApprovalToken {
    private static final Pattern DECIMAL = Pattern.compile("^\\d+(\\.\\d+)?$");

    private ApprovalToken() {
    }

    /**
     * What you are about to execute: each field is checked when set. {@code user}: the person (the
     * token's {@code sub}); {@code type}: the action type; {@code authorizationDetails}: RFC 9396
     * details, one object (matches a token with exactly one entry) or a list (matches entry by entry),
     * any object (a Map, a record, a JsonNode). Amounts compare as decimals, IBANs without spaces in
     * any case, currencies in any case; extra fields of the token are ignored.
     */
    public record Expectation(String user, String type, Object authorizationDetails) {
    }

    /** Header and claims of a token, not verified. */
    public record Decoded(ObjectNode header, ObjectNode claims) {
    }

    /** Header and claims WITHOUT checking the signature. */
    public static Decoded decode(String token) {
        Jws.Parts parts = Jws.split(token);
        if (parts == null) throw new TouchqueApprovalMismatchException("not an approval token");
        return new Decoded(parts.header(), parts.claims());
    }

    /** Does {@code details} (a token's authorization_details) say what {@code expected} says? */
    public static boolean matches(JsonNode details, Object expected) {
        if (details == null || !details.isArray()) return false;
        JsonNode exp = Json.toNode(expected);
        if (exp != null && exp.isArray()) {
            if (details.size() != exp.size()) return false;
            for (int i = 0; i < exp.size(); i++) {
                if (!partial(details.get(i), exp.get(i))) return false;
            }
            return true;
        }
        return details.size() == 1 && partial(details.get(0), exp);
    }

    /** Throws {@link TouchqueApprovalMismatchException} unless the claims say what you expect. */
    public static void assertMatches(JsonNode claims, Expectation expect) {
        if (expect == null) return;
        if (expect.user() != null && !expect.user().equals(Json.str(claims, "sub"))) {
            throw new TouchqueApprovalMismatchException("the approval is for another person");
        }
        if (expect.type() != null && !expect.type().equals(Json.str(claims, "type"))) {
            throw new TouchqueApprovalMismatchException("the approval is for another action type (" + Json.str(claims, "type") + ")");
        }
        if (expect.authorizationDetails() != null && !matches(claims.get("authorization_details"), expect.authorizationDetails())) {
            throw new TouchqueApprovalMismatchException("the approved details differ from what you are about to execute");
        }
    }

    /**
     * Verifies an approval token offline: typ {@code touchque-approval+jwt}, ES256 by a key of
     * {@code jwks}, not expired (30 s leeway), {@code aud} equal to {@code audience}, then {@code expect}.
     * {@code audience} is required: {@code /agents/jwks.json} is one key set for every Touchque
     * workspace, so without it a token Touchque signed for another workspace would pass. Pass your own
     * ({@code tq.agents().approvalAudience()}, {@code touchque:workspace:<id>}), or use
     * {@code tq.agents().verifyApprovalToken}, which fills it in. Does NOT make it single-use.
     */
    public static ObjectNode verifyWith(String token, JsonNode jwks, String audience, Expectation expect) {
        return verifyWith(token, jwks, audience, expect, null);
    }

    public static ObjectNode verifyWith(String token, JsonNode jwks, String audience, Expectation expect, Instant now) {
        if (audience == null || audience.isEmpty()) {
            throw new TouchqueApprovalMismatchException("audience is required: your workspace's touchque:workspace:<id> (tq.agents().approvalAudience())");
        }
        Jws.Parts parts = Jws.split(token);
        if (parts == null) throw new TouchqueApprovalMismatchException("not an approval token");
        if (!"touchque-approval+jwt".equals(Json.str(parts.header(), "typ")) || !"ES256".equals(Json.str(parts.header(), "alg"))) {
            throw new TouchqueApprovalMismatchException("not an approval token (typ/alg)");
        }
        String kid = Json.str(parts.header(), "kid");
        JsonNode jwk = null;
        JsonNode keys = jwks == null ? null : jwks.get("keys");
        if (keys != null && keys.isArray()) {
            for (JsonNode k : keys) {
                if (kid != null && kid.equals(Json.str(k, "kid")) && "EC".equals(Json.str(k, "kty")) && "P-256".equals(Json.str(k, "crv"))) jwk = k;
            }
        }
        if (jwk == null) throw new TouchqueApprovalMismatchException("signed by an unknown key");
        if (!Jws.verify("ES256", jwk, parts.input(), parts.signature())) throw new TouchqueApprovalMismatchException("the signature does not verify");
        long at = (now != null ? now : Instant.now()).getEpochSecond();
        Long exp = Json.lng(parts.claims(), "exp");
        if (exp == null || exp + 30 < at) throw new TouchqueApprovalMismatchException("the approval token expired");
        String aud = Json.str(parts.claims(), "aud");
        if (aud == null || aud.isEmpty()) throw new TouchqueApprovalMismatchException("the approval token names no workspace");
        if (!audience.equals(aud)) throw new TouchqueApprovalMismatchException("the approval token is for another workspace");
        assertMatches(parts.claims(), expect);
        return parts.claims();
    }

    private static String decimalText(JsonNode value) {
        if (value == null || value.isNull() || value.isContainerNode()) return null;
        String text = (value.isTextual() ? value.textValue() : value.toString()).trim();
        if (!DECIMAL.matcher(text).matches()) return null;
        String[] parts = text.split("\\.", 2);
        String whole = parts[0].replaceFirst("^0+", "");
        if (whole.isEmpty()) whole = "0";
        String frac = parts.length > 1 ? parts[1].replaceFirst("0+$", "") : "";
        return frac.isEmpty() ? whole : whole + "." + frac;
    }

    private static boolean same(String key, JsonNode actual, JsonNode expected) {
        if (expected != null && expected.isContainerNode()) return partial(actual, expected);
        if (key.equals("amount")) {
            String a = decimalText(actual);
            return a != null && a.equals(decimalText(expected));
        }
        if (key.equals("iban") || key.equals("currency")) {
            if (actual == null || !actual.isTextual()) return false;
            String e = expected == null ? "" : expected.isTextual() ? expected.textValue() : expected.toString();
            return norm(actual.textValue()).equals(norm(e));
        }
        return scalarEquals(actual, expected);
    }

    private static String norm(String v) {
        return v.replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
    }

    private static boolean partial(JsonNode actual, JsonNode expected) {
        if (expected != null && expected.isArray()) {
            if (actual == null || !actual.isArray() || actual.size() != expected.size()) return false;
            for (int i = 0; i < expected.size(); i++) {
                JsonNode e = expected.get(i);
                if (!(e.isContainerNode() ? partial(actual.get(i), e) : scalarEquals(actual.get(i), e))) return false;
            }
            return true;
        }
        if (expected == null || !expected.isObject()) return scalarEquals(actual, expected);
        if (actual == null || !actual.isObject()) return false;
        Iterator<Map.Entry<String, JsonNode>> it = expected.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            if (!actual.has(e.getKey()) || !same(e.getKey(), actual.get(e.getKey()), e.getValue())) return false;
        }
        return true;
    }

    private static boolean scalarEquals(JsonNode a, JsonNode b) {
        boolean aNull = a == null || a.isNull();
        boolean bNull = b == null || b.isNull();
        if (aNull || bNull) return aNull && bNull;
        if (a.isContainerNode() || b.isContainerNode()) return false;
        if (a.isTextual()) return b.isTextual() && a.textValue().equals(b.textValue());
        if (a.isBoolean()) return b.isBoolean() && a.booleanValue() == b.booleanValue();
        if (a.isNumber() && b.isNumber()) return new BigDecimal(a.asText()).compareTo(new BigDecimal(b.asText())) == 0;
        return a.toString().equals(b.toString());
    }
}
