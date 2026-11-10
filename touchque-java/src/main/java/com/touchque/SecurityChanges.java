package com.touchque;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Json;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/** When the user's sign-in security last changed in your system (access rules read {@code minutesSince.*}). */
public record SecurityChanges(Instant password, Instant mfa, Instant device, Instant email, Instant phone) {
    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    /** The JSON the API takes, or null when nothing is set. */
    public ObjectNode toJson() {
        ObjectNode o = Json.object();
        add(o, "password", password);
        add(o, "mfa", mfa);
        add(o, "device", device);
        add(o, "email", email);
        add(o, "phone", phone);
        return o.isEmpty() ? null : o;
    }

    private static void add(ObjectNode o, String key, Instant at) {
        if (at != null) o.put(key, ISO.format(at));
    }
}
