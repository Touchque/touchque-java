package com.touchque.relay;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Fixed-window rate limiting of the relay's pre-auth routes. */
public final class RateLimit {
    private RateLimit() {
    }

    /**
     * Counter storage for {@link Limiter}. {@link #hit} must atomically count one hit for the key in
     * its current fixed window and return the count in that window (this hit included) and when the
     * window ends (unix ms). A new window (count 1, resetAt = now + window) starts when none is open for
     * the key or the open one has ended. Several instances: implement it over Redis ({@code INCR} +
     * {@code PEXPIRE} when the count is 1, then {@code PTTL}).
     */
    public interface Store {
        Hit hit(String key, long windowMs, long nowMs);
    }

    /** The count in the current window and when it ends (unix ms). */
    public record Hit(int count, long resetAt) {
    }

    /** In-process {@link Store}, bounded: once full, expired windows are dropped, and if it is still full the oldest half goes. */
    public static final class MemoryStore implements Store {
        private final Map<String, Hit> entries = new HashMap<>();
        private final int maxEntries;

        public MemoryStore() {
            this(50_000);
        }

        public MemoryStore(int maxEntries) {
            this.maxEntries = Math.max(2, maxEntries);
        }

        @Override
        public synchronized Hit hit(String key, long windowMs, long nowMs) {
            Hit entry = entries.get(key);
            if (entry == null || entry.resetAt() <= nowMs) {
                if (!entries.containsKey(key) && entries.size() >= maxEntries) prune(nowMs);
                entry = new Hit(0, nowMs + windowMs);
            }
            entry = new Hit(entry.count() + 1, entry.resetAt());
            entries.put(key, entry);
            return entry;
        }

        private void prune(long nowMs) {
            entries.values().removeIf(h -> h.resetAt() <= nowMs);
            if (entries.size() >= maxEntries) {
                // Still full (a flood of distinct keys): drop the oldest half rather than grow without bound.
                List<Map.Entry<String, Hit>> sorted = new ArrayList<>(entries.entrySet());
                sorted.sort((a, b) -> Long.compare(a.getValue().resetAt(), b.getValue().resetAt()));
                for (int i = 0; i <= maxEntries / 2 && i < sorted.size(); i++) entries.remove(sorted.get(i).getKey());
            }
        }
    }

    /** Rate limits of the relay's pre-auth routes: per client IP and per username, per route, per window. */
    public record Options(Duration window, int perIp, int perUser, Store store) {
        /** 20 per IP and 5 per username a minute, in this process. */
        public static Options defaults() {
            return new Options(Duration.ofMinutes(1), 20, 5, null);
        }
    }

    /** Fixed-window rate limiter: protects your server (and your Touchque quota) from scripted abuse of public routes. */
    public static final class Limiter {
        private final long windowMs;
        private final int perIp;
        private final int perUser;
        private final Store store;

        public Limiter(Options options) {
            Options o = options != null ? options : Options.defaults();
            this.windowMs = (o.window() != null ? o.window() : Duration.ofMinutes(1)).toMillis();
            this.perIp = o.perIp();
            this.perUser = o.perUser();
            this.store = o.store() != null ? o.store() : new MemoryStore();
        }

        public int perIp() {
            return perIp;
        }

        public int perUser() {
            return perUser;
        }

        /** Counts one hit. Returns seconds to wait when over the limit, otherwise 0. */
        public int hit(String key, int limit) {
            long now = System.currentTimeMillis();
            Hit h = store.hit(key, windowMs, now);
            if (h.count() <= limit) return 0;
            return (int) Math.max(1, Math.ceil((h.resetAt() - now) / 1000.0));
        }
    }
}
