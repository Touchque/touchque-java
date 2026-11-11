package com.touchque.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.touchque.internal.Json;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** The shared Node fake Touchque API (testing/fake-touchque-api.mjs), one per test run. */
final class FakeApi {
    private static FakeApi shared;
    final String baseUrl;
    private final HttpClient http = HttpClient.newHttpClient();

    private FakeApi() throws IOException {
        Path dir = Path.of("").toAbsolutePath();
        while (dir != null && !Files.exists(dir.resolve("testing/fake-touchque-api.mjs"))) dir = dir.getParent();
        if (dir == null) throw new IllegalStateException("Could not find testing/fake-touchque-api.mjs");
        Process process = new ProcessBuilder("node", dir.resolve("testing/fake-touchque-api.mjs").toString()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        Runtime.getRuntime().addShutdownHook(new Thread(process::destroy));
        String line = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)).readLine();
        baseUrl = "http://127.0.0.1:" + Json.parse(line).get("port").asInt();
    }

    static synchronized FakeApi get() {
        if (shared == null) {
            try {
                shared = new FakeApi();
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return shared;
    }

    JsonNode post(String path, Object body) throws Exception {
        HttpResponse<String> res = http.send(HttpRequest.newBuilder(URI.create(baseUrl + path)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Json.write(Json.toNode(body)))).build(), HttpResponse.BodyHandlers.ofString());
        return Json.parse(res.body());
    }

    JsonNode get(String path) throws Exception {
        return Json.parse(http.send(HttpRequest.newBuilder(URI.create(baseUrl + path)).build(), HttpResponse.BodyHandlers.ofString()).body());
    }
}
