package com.touchque;

/** A reason code and its English text (number matching, silent sign-ins, "Why?"). {@code action}: what to do about it, when Touchque says. */
public record RiskReason(String code, String text, String action) {
}
