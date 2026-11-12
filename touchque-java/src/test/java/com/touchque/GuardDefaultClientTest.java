package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.flow.Guard;
import com.touchque.internal.Json;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Guard.run(null, …) and Guard.isStatusPoll(null, …): the default client, built from the
 * environment. Each case runs in a JVM of its own, so this test sets the environment it needs
 * whatever the developer's shell has.
 */
class GuardDefaultClientTest {
    private final Support.FakeApi api = Support.FakeApi.get();

    /** The child JVM: runs the guard with no client and prints what it saw as one JSON object. */
    public static final class Child {
        public static void main(String[] args) throws Exception {
            ObjectNode out = Json.object();
            String user = args[0];
            Guard.Result anonymous = Guard.run(null, new Guard.Input(null, "LOGIN"));
            out.put("anonymous", anonymous.status());
            Guard.Result first = Guard.run(null, new Guard.Input(user, "LOGIN"));
            out.put("first", first.status());
            out.set("firstBody", first.body());
            String token = first.body().has("token") ? first.body().get("token").asText() : "v1.x.y";
            out.put("statusPoll", Guard.isStatusPoll(null, new Guard.Input(user, "LOGIN").token(token)));
            if (first.status() == 202) {
                // Built once and kept: every thread gets the same client.
                ExecutorService pool = Executors.newFixedThreadPool(8);
                List<Future<TouchqueClient>> clients = new ArrayList<>();
                for (int i = 0; i < 32; i++) clients.add(pool.submit((Callable<TouchqueClient>) Guard::defaultClient));
                Set<TouchqueClient> distinct = new HashSet<>();
                for (Future<TouchqueClient> f : clients) distinct.add(f.get());
                pool.shutdown();
                out.put("sameClient", distinct.size() == 1 && distinct.contains(Guard.defaultClient()));
                out.put("poll", Guard.run(null, new Guard.Input(user, "LOGIN").token(token)).status());
                HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(System.getenv("TQ_API_URL") + "/__test/approve"))
                        .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{\"via\":\"DEVICE\"}")).build(),
                        HttpResponse.BodyHandlers.discarding());
                Guard.Result done = Guard.run(null, new Guard.Input(user, "LOGIN").token(token));
                out.put("approved", done.approved() != null ? done.approved().confirmedVia() : "no");
            } else {
                // Not kept: the next request tries again (and answers the same while the keys are missing).
                out.put("again", Guard.run(null, new Guard.Input(user, "LOGIN")).status());
            }
            System.out.println(Json.write(out));
        }
    }

    private static JsonNode child(Map<String, String> env, String user) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"), Child.class.getName(), user);
        pb.environment().keySet().removeIf(k -> k.startsWith("TQ_"));
        pb.environment().putAll(env);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        p.waitFor(60, TimeUnit.SECONDS);
        assertEquals(0, p.exitValue(), out);
        String[] lines = out.split("\n");
        return Json.parse(lines[lines.length - 1]);
    }

    @Test
    void withoutKeysTheNullClientAnswers401Or500Misconfigured() throws Exception {
        JsonNode seen = child(Map.of(), "jane@acme.com");
        assertEquals(List.of(401, 500, false, 500), List.of(seen.get("anonymous").asInt(), seen.get("first").asInt(), seen.get("statusPoll").asBoolean(),
                seen.get("again").asInt()));
        assertEquals(Json.parse("{\"touchque\":{\"state\":\"blocked\",\"reason\":\"misconfigured\"},"
                + "\"error\":{\"code\":\"misconfigured\",\"message\":\"Two-factor approval is not configured correctly.\"}}"), seen.get("firstBody"));
    }

    @Test
    void withKeysTheNullClientIsBuiltFromTheEnvironmentOnceAndWorks() throws Exception {
        api.reset();
        api.link("env@acme.com");
        JsonNode seen = child(Map.of("TQ_API_KEY", "tq_test_key", "TQ_API_SECRET", "test_secret", "TQ_API_URL", api.baseUrl), "env@acme.com");
        assertEquals(List.of(401, 202, "waiting", true, true, 202, "DEVICE"), List.of(seen.get("anonymous").asInt(), seen.get("first").asInt(),
                seen.get("firstBody").get("touchque").get("state").asText(), seen.get("statusPoll").asBoolean(), seen.get("sameClient").asBoolean(),
                seen.get("poll").asInt(), seen.get("approved").asText()));
        // The requests were signed with the environment's key.
        ArrayNode calls = api.calls();
        assertEquals("/login/request", calls.get(0).get("path").asText());
    }
}
