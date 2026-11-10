package com.touchque;

import java.util.List;

/**
 * Where an action sends money or value; the phone shows it in full, grouped by four.
 * {@code kind}: iban, account, wallet, address or payee. {@code known}: destinations this user
 * used before; a look-alike of one is flagged on the phone.
 */
public record Destination(String kind, String value, List<String> known) {
    public static Destination of(String kind, String value) {
        return new Destination(kind, value, null);
    }
}
