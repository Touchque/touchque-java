package com.touchque.relay;

/** What {@code onAuthenticated} learns: who signed in, and how ({@code via}: login, passkey, offline, offline-totp or silent). */
public record RelayAuthenticated(String externalUsername, String requestId, String via) {
}
