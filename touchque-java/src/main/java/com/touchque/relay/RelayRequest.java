package com.touchque.relay;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.function.Function;

/**
 * One relay request, framework-neutral. {@code method}: HTTP method (HEAD is treated as GET).
 * {@code path}: relative to where the relay is mounted, e.g. {@code /login}. {@code body}: the decoded
 * JSON body (empty for none). {@code ip}: the real client IP ("" when unknown; behind a proxy, resolve
 * it from trusted proxy headers first). {@code header}: a case-insensitive request header getter.
 * {@code nativeRequest}: your framework's request, passed to the option callbacks.
 */
public record RelayRequest<T>(String method, String path, ObjectNode body, String ip, String userAgent, Function<String, String> header, T nativeRequest) {
}
