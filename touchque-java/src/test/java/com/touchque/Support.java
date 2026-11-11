package com.touchque;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.touchque.internal.Json;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/** Test helpers: the shared fixtures, the shared Node fake API, and a local stub server. */
public final class Support {
    private Support() {
    }

    /** The repository root: where testing/ and fixtures/ live. */
    public static final Path SHARED_ROOT = findRoot();

    private static Path findRoot() {
        Path dir = Path.of("").toAbsolutePath();
        while (dir != null) {
            if (Files.exists(dir.resolve("testing/fake-touchque-api.mjs")) && Files.isDirectory(dir.resolve("fixtures"))) return dir;
            dir = dir.getParent();
        }
        throw new IllegalStateException("Could not find testing/fake-touchque-api.mjs above " + Path.of("").toAbsolutePath());
    }

    public static ObjectNode fixture(String name) {
        try {
            return (ObjectNode) Json.MAPPER.readTree(Files.readString(SHARED_ROOT.resolve("fixtures").resolve(name)));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The shared Node fake Touchque API (testing/fake-touchque-api.mjs): it verifies this
     * SDK's request signatures exactly like the real API, over a real HTTP round trip.
     */
    public static final class FakeApi implements AutoCloseable {
        private static FakeApi shared;
        private final Process process;
        private final HttpClient http = HttpClient.newHttpClient();
        public final String baseUrl;

        private FakeApi() throws IOException {
            process = new ProcessBuilder("node", SHARED_ROOT.resolve("testing/fake-touchque-api.mjs").toString())
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start();
            String line = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)).readLine();
            JsonNode port = Json.parse(line == null ? "{}" : line).get("port");
            if (port == null) throw new IllegalStateException("no port: " + line);
            baseUrl = "http://127.0.0.1:" + port.asInt();
        }

        /** One fake API for the whole test run (stopped when the JVM exits). */
        public static synchronized FakeApi get() {
            if (shared == null) {
                try {
                    shared = new FakeApi();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                Runtime.getRuntime().addShutdownHook(new Thread(shared::close));
            }
            return shared;
        }

        public TouchqueClient client() {
            return new TouchqueClient(new TouchqueOptions().apiKey("tq_test_key").apiSecret("test_secret").baseUrl(baseUrl));
        }

        /** A /__test/ call of the fake: its JSON answer. */
        public JsonNode post(String path, Object body) {
            return send(HttpRequest.newBuilder(URI.create(baseUrl + path)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(Json.write(body == null ? Json.object() : Json.toNode(body)))));
        }

        public JsonNode get(String path) {
            return send(HttpRequest.newBuilder(URI.create(baseUrl + path)).GET());
        }

        private JsonNode send(HttpRequest.Builder req) {
            try {
                return Json.parse(http.send(req.build(), HttpResponse.BodyHandlers.ofString()).body());
            } catch (IOException e) {
                throw new IllegalStateException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }

        public void reset() {
            post("/__test/reset", null);
        }

        public void link(String user) {
            post("/__test/link", Map.of("user", user));
        }

        public void opts(Map<String, Object> opts) {
            post("/__test/opts", opts);
        }

        public void approve(String id) {
            ObjectNode b = Json.object().put("via", "DEVICE").put("provisional", false);
            if (id != null) b.put("id", id);
            post("/__test/approve", b);
        }

        public void reject(String id) {
            ObjectNode b = Json.object();
            if (id != null) b.put("id", id);
            post("/__test/reject", b);
        }

        public void escalate(String id) {
            ObjectNode b = Json.object();
            if (id != null) b.put("id", id);
            post("/__test/escalate", b);
        }

        public ArrayNode calls() {
            return (ArrayNode) get("/__test/calls");
        }

        public JsonNode lastCall() {
            ArrayNode calls = calls();
            return calls.get(calls.size() - 1);
        }

        @Override
        public void close() {
            process.destroy();
            try {
                process.waitFor(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** What a stub server saw of one request. */
    public record Seen(String method, String path, Map<String, java.util.List<String>> headers, String body) {
        public String header(String name) {
            for (Map.Entry<String, java.util.List<String>> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) return e.getValue().get(0);
            }
            return null;
        }
    }

    /** A stub answer: status, JSON body and extra headers. */
    public record Answer(int status, Object body, Map<String, String> headers) {
        public static Answer json(int status, Object body) {
            return new Answer(status, body, Map.of());
        }
    }

    /** A local HTTP server answering every request with {@code handler}. */
    public static final class Stub implements AutoCloseable {
        private final HttpServer server;
        public final String baseUrl;

        public Stub(Function<Seen, Answer> handler) throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> handle(exchange, handler));
            server.start();
            baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        }

        private static void handle(HttpExchange exchange, Function<Seen, Answer> handler) throws IOException {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Answer a = handler.apply(new Seen(exchange.getRequestMethod(), exchange.getRequestURI().toString(), exchange.getRequestHeaders(), body));
            byte[] out = a.body() == null ? new byte[0] : (a.body() instanceof String s ? s : Json.write(Json.toNode(a.body()))).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            a.headers().forEach((k, v) -> exchange.getResponseHeaders().set(k, v));
            exchange.sendResponseHeaders(a.status(), out.length == 0 ? -1 : out.length);
            if (out.length > 0) exchange.getResponseBody().write(out);
            exchange.close();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
