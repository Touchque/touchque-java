package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.agents.CrossAppAccess;
import com.touchque.crypto.Jws;
import com.touchque.internal.Json;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.IntFunction;
import org.junit.jupiter.api.Test;

/**
 * requestIdJag and redeemIdJag against a raw HTTP/1.1 token endpoint on this machine, which sends what an in-process
 * HttpServer will not: headers the JDK's HttpClient refuses, cut and oversized bodies, closed and refused connections.
 * Only a 2xx answer with a JSON object is an answer. Any other status (redirects included) is an error with the body's
 * RFC 6749 error code, else server_error; a server that cannot be reached or read is temporarily_unavailable with the
 * failure as the cause and no status; and every error carries the latest valid DPoP-Nonce of the call.
 */
class IdJagTransportTest {
    private static final String NONCE_REFUSAL = "{\"error\":\"use_dpop_nonce\",\"error_description\":\"send a nonce\"}";
    private static final String TOKENS = "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}";
    /** No answer at all: the connection stays open until the endpoint closes. */
    private static final byte[] HANG = new byte[0];
    /** The JDK's HttpClient without the SDK, to see what it refuses by itself. */
    private static final HttpClient PLAIN = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    /** Bytes as they go on the wire: each char of {@code s} as one ISO-8859-1 byte (control bytes included). */
    private static byte[] raw(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** An HTTP/1.1 answer: status, the headers as name, value pairs, Content-Length and the body (UTF-8). */
    private static byte[] answer(int status, String body, String... headers) {
        StringBuilder head = new StringBuilder("HTTP/1.1 ").append(status).append(" X\r\n");
        for (int i = 0; i < headers.length; i += 2) head.append(headers[i]).append(": ").append(headers[i + 1]).append("\r\n");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        head.append("Content-Type: application/json\r\nContent-Length: ").append(bytes.length).append("\r\nConnection: close\r\n\r\n");
        return concat(raw(head.toString()), bytes);
    }

    /** What the endpoint received: the request line and the DPoP header (null without one). */
    record Received(String requestLine, String dpop) {
        String nonce() {
            return dpop == null ? null : Json.str(Jws.split(dpop).claims(), "nonce");
        }

        String target() {
            return requestLine.split(" ")[1];
        }
    }

    /** A token endpoint on a server socket: answers request n with {@code script.apply(n)} (null: closes without one). */
    private static final class RawEndpoint implements AutoCloseable {
        final List<Received> received = new CopyOnWriteArrayList<>();
        final CountDownLatch arrived = new CountDownLatch(1);
        final String base;
        final String url;
        private final ServerSocket server;
        private final IntFunction<byte[]> script;
        private final List<Socket> sockets = new CopyOnWriteArrayList<>();
        private final CountDownLatch closed = new CountDownLatch(1);

        RawEndpoint(IntFunction<byte[]> script) throws IOException {
            this.script = script;
            server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            base = "http://127.0.0.1:" + server.getLocalPort();
            url = base + "/token";
            Thread accept = new Thread(() -> {
                while (true) {
                    try {
                        Socket s = server.accept();
                        sockets.add(s);
                        Thread t = new Thread(() -> serve(s), "raw-token-endpoint");
                        t.setDaemon(true);
                        t.start();
                    } catch (IOException e) {
                        return;   // closed
                    }
                }
            }, "raw-token-endpoint-accept");
            accept.setDaemon(true);
            accept.start();
        }

        /** The request head up to its blank line (ISO-8859-1), or null when the client closed first. */
        private static String readHead(InputStream in) throws IOException {
            StringBuilder head = new StringBuilder();
            int c;
            while ((c = in.read()) >= 0) {
                head.append((char) c);
                int n = head.length();
                if (n >= 4 && head.charAt(n - 4) == '\r' && head.charAt(n - 3) == '\n' && head.charAt(n - 2) == '\r' && head.charAt(n - 1) == '\n') {
                    return head.toString();
                }
            }
            return null;
        }

        private void serve(Socket s) {
            try (s) {
                InputStream in = s.getInputStream();
                String head = readHead(in);
                if (head == null) return;
                String[] lines = head.split("\r\n");
                int length = 0;
                String dpop = null;
                for (String line : lines) {
                    int colon = line.indexOf(':');
                    if (colon < 0) continue;
                    String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                    if (name.equals("content-length")) length = Integer.parseInt(line.substring(colon + 1).trim());
                    if (name.equals("dpop")) dpop = line.substring(colon + 1).trim();
                }
                in.readNBytes(length);
                int n;
                synchronized (received) {
                    n = received.size();
                    received.add(new Received(lines[0], dpop));
                }
                arrived.countDown();
                byte[] out = script.apply(n);
                if (out == HANG) {
                    closed.await(20, TimeUnit.SECONDS);
                    return;
                }
                if (out != null) {
                    OutputStream os = s.getOutputStream();
                    os.write(out);
                    os.flush();
                }
                s.shutdownOutput();
                // Until the client closes: closing first, with bytes of its request unread, could reset the connection.
                s.setSoTimeout(5000);
                in.transferTo(OutputStream.nullOutputStream());
            } catch (IOException | InterruptedException e) {
                // the client went away
            }
        }

        List<String> nonces() {
            return received.stream().map(Received::nonce).toList();
        }

        @Override
        public void close() throws IOException {
            closed.countDown();
            server.close();
            for (Socket s : sockets) s.close();
        }
    }

    private static ObjectNode redeem(String url, CrossAppAccess.IdJagDpopKey key) {
        return CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions(url, "acme-at-rs", "the.id.jag").clientSecret("rs_secret").dpopKey(key));
    }

    private static TouchqueIdJagException redeemFails(String url, CrossAppAccess.IdJagDpopKey key) {
        return assertThrows(TouchqueIdJagException.class, () -> redeem(url, key));
    }

    private static TouchqueIdJagException requestFails(String url, CrossAppAccess.IdJagDpopKey key) {
        return assertThrows(TouchqueIdJagException.class, () -> CrossAppAccess.requestIdJag(
                new CrossAppAccess.RequestOptions("tqapp_test", "tqs_test", "idtoken:ada", "https://rs.example").tokenEndpoint(url).dpopKey(key)));
    }

    /** error, status and dpopNonce, for one assertEquals. */
    private static List<Object> of(TouchqueIdJagException e) {
        return Arrays.asList(e.error(), e.status(), e.dpopNonce());
    }

    /**
     * Whether the JDK's own HttpClient refuses this answer (control bytes in a header value; over 384 KB of headers with
     * jdk.http.maxHeaderSize, as 21.0.10 does). Such cases run only where it does, so the test holds on every JDK.
     */
    private static boolean jdkRefuses(byte[] answer) throws Exception {
        try (RawEndpoint ep = new RawEndpoint(n -> answer)) {
            PLAIN.send(HttpRequest.newBuilder(URI.create(ep.url)).POST(HttpRequest.BodyPublishers.ofString("x")).build(), HttpResponse.BodyHandlers.discarding());
            return false;
        } catch (IOException e) {
            return true;
        }
    }

    @Test
    void anAnswerThatCannotBeReadIsTemporarilyUnavailable() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        byte[] big = new byte[10 * 1024 * 1024 + 1];
        Arrays.fill(big, (byte) 'a');
        record Case(String what, byte[] answer, String nonce, Class<? extends Throwable> cause) {
        }
        List<Case> cases = new ArrayList<>(List.of(
                new Case("closed without an answer", null, null, IOException.class),
                new Case("not an HTTP status line", raw("HTTP/1.1 abc OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), null, IOException.class),
                // Headers with a valid nonce, then a body cut off or over 10 MB: that answer's nonce goes along.
                new Case("a cut body", raw("HTTP/1.1 200 OK\r\nDPoP-Nonce: n-1\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"access_token\":"),
                        "n-1", IOException.class),
                new Case("a body over 10 MB", concat(raw("HTTP/1.1 400 X\r\nDPoP-Nonce: n-1\r\nContent-Length: " + big.length + "\r\nConnection: close\r\n\r\n"), big),
                        "n-1", TouchqueNetworkException.class)));
        for (Case refused : List.of(
                new Case("NUL in a header", answer(400, NONCE_REFUSAL, "DPoP-Nonce", "n\u00001"), null, IOException.class),
                new Case("0x01 in a header", answer(400, NONCE_REFUSAL, "DPoP-Nonce", "n\u00011"), null, IOException.class),
                new Case("DEL in a header", answer(400, NONCE_REFUSAL, "DPoP-Nonce", "n\u007f1"), null, IOException.class),
                new Case("over 384 KB of headers", answer(200, TOKENS, "X-Big", "a".repeat(400_000)), null, IOException.class))) {
            if (jdkRefuses(refused.answer())) cases.add(refused);
        }
        for (Case c : cases) {
            for (boolean request : List.of(false, true)) {
                String what = c.what() + (request ? " (requestIdJag)" : " (redeemIdJag)");
                try (RawEndpoint ep = new RawEndpoint(n -> c.answer())) {
                    TouchqueIdJagException e = request ? requestFails(ep.url, key) : redeemFails(ep.url, key);
                    assertEquals(Arrays.asList("temporarily_unavailable", null, c.nonce()), of(e), what);
                    assertInstanceOf(c.cause(), e.getCause(), what);
                    assertTrue(e.getMessage().startsWith(ep.url + ": "), what + ": " + e.getMessage());
                    assertEquals(1, ep.received.size(), what);
                }
            }
        }
    }

    @Test
    void aRefusedConnectionIsTemporarilyUnavailable() throws Exception {
        String url;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            url = "http://127.0.0.1:" + s.getLocalPort() + "/token";
        }
        for (TouchqueIdJagException e : List.of(redeemFails(url, CrossAppAccess.createIdJagDpopKey()), redeemFails(url, null), requestFails(url, null))) {
            assertEquals(Arrays.asList("temporarily_unavailable", null, null), of(e));
            assertInstanceOf(ConnectException.class, e.getCause());
            assertTrue(e.getMessage().startsWith(url + ": "), e.getMessage());
        }
    }

    @Test
    void aFailedRetryCarriesTheLatestNonce() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        byte[] first = answer(400, NONCE_REFUSAL, "DPoP-Nonce", "n-1");
        record Case(String what, byte[] retry, List<Object> error) {
        }
        List<Case> cases = List.of(
                new Case("closed without an answer", null, Arrays.asList("temporarily_unavailable", null, "n-1")),
                new Case("not an HTTP status line", raw("HTTP/1.1 abc OK\r\nDPoP-Nonce: n-2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
                        Arrays.asList("temporarily_unavailable", null, "n-1")),
                new Case("a cut body after a new nonce", raw("HTTP/1.1 200 OK\r\nDPoP-Nonce: n-2\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{"),
                        Arrays.asList("temporarily_unavailable", null, "n-2")),
                new Case("a cut body after an invalid nonce", raw("HTTP/1.1 200 OK\r\nDPoP-Nonce: n 2\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{"),
                        Arrays.asList("temporarily_unavailable", null, "n-1")),
                new Case("a redirect with a new nonce", answer(302, TOKENS, "Location", "/token/moved", "DPoP-Nonce", "n-2"), Arrays.asList("server_error", 302, "n-2")),
                new Case("a 200 without a JSON object", answer(200, "null"), Arrays.asList("invalid_response", 200, "n-1")),
                new Case("a 201 without a JSON object, a new nonce", answer(201, "[]", "DPoP-Nonce", "n-2"), Arrays.asList("invalid_response", 201, "n-2")));
        for (Case c : cases) {
            try (RawEndpoint ep = new RawEndpoint(n -> n == 0 ? first : c.retry())) {
                assertEquals(c.error(), of(redeemFails(ep.url, key)), c.what());
                assertEquals(Arrays.asList(null, "n-1"), ep.nonces(), c.what());   // one retry, with the first nonce
            }
        }
    }

    @Test
    void anInterruptedCallStaysInterrupted() throws Exception {
        try (RawEndpoint ep = new RawEndpoint(n -> HANG)) {
            AtomicReference<Throwable> thrown = new AtomicReference<>();
            AtomicBoolean interrupted = new AtomicBoolean();
            Thread caller = new Thread(() -> {
                try {
                    redeem(ep.url, CrossAppAccess.createIdJagDpopKey());
                } catch (Throwable e) {
                    thrown.set(e);
                }
                interrupted.set(Thread.currentThread().isInterrupted());
            });
            caller.start();
            assertTrue(ep.arrived.await(10, TimeUnit.SECONDS));
            caller.interrupt();
            caller.join(10_000);
            TouchqueIdJagException e = assertInstanceOf(TouchqueIdJagException.class, thrown.get());
            assertEquals(Arrays.asList("temporarily_unavailable", null, null), of(e));
            assertInstanceOf(InterruptedException.class, e.getCause());
            assertTrue(interrupted.get(), "the caller's interrupt status is restored");
        }
    }

    @Test
    void aRedirectIsARefusalAndNeverFollowed() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        for (int status : List.of(300, 301, 302, 303, 307, 308)) {
            try (RawEndpoint ep = new RawEndpoint(n -> answer(status, TOKENS, "Location", "/token/moved", "DPoP-Nonce", "n-3"))) {
                assertEquals(Arrays.asList("server_error", status, "n-3"), of(redeemFails(ep.url, key)), "redeemIdJag " + status);
                assertEquals(Arrays.asList("server_error", status, "n-3"), of(requestFails(ep.url, null)), "requestIdJag " + status);
                assertEquals(List.of("/token", "/token"), ep.received.stream().map(Received::target).toList());
            }
        }
        // A redirect's body may name the error.
        try (RawEndpoint ep = new RawEndpoint(n -> answer(302, "{\"error\":\"invalid_request\",\"error_description\":\"moved\"}", "Location", "/token/moved"))) {
            TouchqueIdJagException e = redeemFails(ep.url, null);
            assertEquals(Arrays.asList("invalid_request", 302, null), of(e));
            assertEquals("moved", e.getMessage());
        }
    }

    @Test
    void a2xxWithoutAJsonObjectIsAnInvalidResponse() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        List<String> bodies = List.of("", "  ", "null", "[]", "[" + TOKENS + "]", "\"at\"", "1", "true", "<html>hi</html>", "{", TOKENS + "x", TOKENS + " {}");
        for (int status : List.of(200, 201)) {
            for (String body : bodies) {
                String what = status + " '" + body + "'";
                try (RawEndpoint ep = new RawEndpoint(n -> answer(status, body, "DPoP-Nonce", "n-1"))) {
                    TouchqueIdJagException e = redeemFails(ep.url, key);
                    assertEquals(Arrays.asList("invalid_response", status, "n-1"), of(e), what);
                    assertEquals(ep.url + " answered " + status + " without a JSON object", e.getMessage(), what);
                    assertEquals(Arrays.asList("invalid_response", status, "n-1"), of(requestFails(ep.url, key)), what);
                    assertEquals(2, ep.received.size(), what);
                }
            }
        }
        // 204 No Content: the same, and no nonce without the header.
        try (RawEndpoint ep = new RawEndpoint(n -> raw("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))) {
            assertEquals(Arrays.asList("invalid_response", 204, null), of(redeemFails(ep.url, null)));
            assertEquals(Arrays.asList("invalid_response", 204, null), of(requestFails(ep.url, null)));
        }
        // A JSON object with whitespace around it is the answer, from any 2xx.
        try (RawEndpoint ep = new RawEndpoint(n -> answer(n == 0 ? 200 : 203, " \r\n" + TOKENS + "\r\n "))) {
            assertEquals("at", Json.str(redeem(ep.url, key), "access_token"));
            assertEquals("at", Json.str(redeem(ep.url, null), "access_token"));
        }
        // requestIdJag: a JSON object that holds no ID-JAG stays invalid_response without a status.
        try (RawEndpoint ep = new RawEndpoint(n -> answer(200, TOKENS, "DPoP-Nonce", "n-1"))) {
            assertEquals(Arrays.asList("invalid_response", null, "n-1"), of(requestFails(ep.url, key)));
        }
    }

    @Test
    void theCodeIsTheBodysRfc6749ErrorElseServerError() throws Exception {
        StringBuilder allowed = new StringBuilder();
        for (char c = 0x20; c <= 0x7e; c++) if (c != '"' && c != '\\') allowed.append(c);   // %x20-21 / %x23-5B / %x5D-7E
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put(Json.write(Json.object().put("error", "invalid_grant").put("error_description", "expired")), "invalid_grant");
        cases.put(Json.write(Json.object().put("error", allowed.toString())), allowed.toString());
        cases.put(Json.write(Json.object().put("error", "e".repeat(128))), "e".repeat(128));
        cases.put(Json.write(Json.object().put("error", "e".repeat(129))), "server_error");
        cases.put(Json.write(Json.object().put("error", "")), "server_error");
        cases.put(Json.write(Json.object().put("error", "invalid\"grant")), "server_error");
        cases.put(Json.write(Json.object().put("error", "invalid\\grant")), "server_error");
        cases.put(Json.write(Json.object().put("error", "invalid_gr\u00e4nt")), "server_error");
        cases.put(Json.write(Json.object().put("error", "invalid\u007fgrant")), "server_error");
        cases.put(Json.write(Json.object().put("error", "invalid\tgrant")), "server_error");
        cases.put(Json.write(Json.object().put("error", "invalid\u0000grant")), "server_error");
        cases.put("{\"error\":5}", "server_error");
        cases.put("{\"error\":null}", "server_error");
        cases.put("{\"error\":true}", "server_error");
        cases.put("{\"error\":[\"invalid_grant\"]}", "server_error");
        cases.put("{\"error\":{\"code\":\"invalid_grant\"}}", "server_error");
        cases.put("{}", "server_error");
        cases.put("", "server_error");
        cases.put("invalid_grant", "server_error");
        cases.put("{\"error\":\"invalid_grant\"}x", "server_error");   // not one JSON object
        for (int status : List.of(400, 401, 403, 500, 503)) {
            for (Map.Entry<String, String> c : cases.entrySet()) {
                String what = status + " " + c.getKey();
                // WWW-Authenticate never gives the code.
                try (RawEndpoint ep = new RawEndpoint(n -> answer(status, c.getKey(), "WWW-Authenticate", "DPoP error=\"invalid_token\""))) {
                    TouchqueIdJagException e = redeemFails(ep.url, null);
                    assertEquals(Arrays.asList(c.getValue(), status, null), of(e), what);
                    assertNull(e.getCause(), what);
                }
            }
        }
    }

    @Test
    void aRepeatedNonceCountsOnlyWhenEveryValueIsTheSame() throws Exception {
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        try (RawEndpoint ep = new RawEndpoint(n -> n > 0 ? answer(200, TOKENS)
                : answer(400, NONCE_REFUSAL, "DPoP-Nonce", "n-1", "DPoP-Nonce", "n-1", "DPoP-Nonce", "n-1"))) {
            redeem(ep.url, key);
            assertEquals(Arrays.asList(null, "n-1"), ep.nonces());
        }
        List<List<String>> conflicting = List.of(List.of("n-1", "n-1", "n-2"), List.of("n-2", "n-1", "n-1"), List.of("n-1", "n 1"), List.of("n-1, n-2"));
        for (List<String> values : conflicting) {
            List<String> headers = new ArrayList<>();
            values.forEach(v -> headers.addAll(List.of("DPoP-Nonce", v)));
            try (RawEndpoint ep = new RawEndpoint(n -> answer(400, NONCE_REFUSAL, headers.toArray(String[]::new)))) {
                assertEquals(Arrays.asList("use_dpop_nonce", 400, null), of(redeemFails(ep.url, key)), values.toString());
                assertEquals(1, ep.received.size(), values.toString());
            }
        }
    }

    @Test
    void htuIsThePathTheClientSends() throws Exception {
        // Dot segments, percent-encoding and raw non-ASCII: the request-target on the wire is the proof's htu path.
        List<String> paths = List.of("/a/../token", "/x/./token", "/t/%7e", "/a/%2e%2e/token", "/t/a%20b", "/t/a~b", "/t/%C3%BC", "/t/\u00fc", "/t/u\u0308", "//token");
        CrossAppAccess.IdJagDpopKey key = CrossAppAccess.createIdJagDpopKey();
        try (RawEndpoint ep = new RawEndpoint(n -> answer(200, TOKENS))) {
            for (String path : paths) redeem(ep.base + path, key);
            assertEquals(paths.size(), ep.received.size());
            for (Received r : ep.received) {
                String htu = Json.str(Jws.split(r.dpop()).claims(), "htu");
                assertEquals(r.target(), URI.create(htu).getRawPath(), htu);
                assertTrue(htu.startsWith(ep.base + "/"), htu);
            }
        }
    }
}
