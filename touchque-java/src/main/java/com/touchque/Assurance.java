package com.touchque;

/**
 * How strongly an approval was made. {@code phishingResistant} is true for a passkey;
 * {@code method} is push, passkey, offline_code, offline_totp or silent.
 */
public record Assurance(boolean phishingResistant, String method) {
}
