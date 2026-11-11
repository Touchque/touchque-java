package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Json;
import com.touchque.resources.Actions;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Touchque Actions: every management call sends exactly what fixtures/actions-api-vectors.json says. */
class ActionsTest {
    private final Support.FakeApi api = Support.FakeApi.get();

    @BeforeEach
    void reset() {
        api.reset();
    }

    private static List<String> list(JsonNode n) {
        if (n == null || !n.isArray()) return null;
        List<String> out = new ArrayList<>();
        n.forEach(x -> out.add(x.asText()));
        return out;
    }

    private static JsonNode call(TouchqueClient tq, String name, JsonNode a) {
        Actions acts = tq.actions();
        return switch (name) {
            case "deploy" -> acts.deploy(Json.str(a, "slug"), new Actions.DeployOptions().trigger(Json.str(a, "trigger")).code(Json.str(a, "code"))
                    .secrets(list(a.get("secrets"))).name(Json.str(a, "name")));
            case "deployTemplate" -> acts.deploy(Json.str(a, "slug"), new Actions.DeployOptions().trigger(Json.str(a, "trigger"))
                    .template(Actions.TemplateRef.of(a.get("template").get("id").asText(), a.get("template").get("params"))).onFailure(Json.str(a, "onFailure")));
            case "deployLoosening" -> acts.deploy(Json.str(a, "slug"), new Actions.DeployOptions().trigger(Json.str(a, "trigger")).code(Json.str(a, "code"))
                    .capabilities(list(a.get("capabilities"))).allowedHosts(list(a.get("allowedHosts"))));
            case "list" -> acts.list();
            case "get" -> acts.get(Json.str(a, "slug"));
            case "version" -> acts.version(Json.str(a, "slug"), a.get("number").asInt());
            case "update" -> acts.update(Json.str(a, "slug"), null, a.has("enabled") ? a.get("enabled").asBoolean() : null, null, null);
            case "rollback" -> acts.rollback(Json.str(a, "slug"), Json.integer(a, "version"));
            case "rollbackPrevious" -> acts.rollback(Json.str(a, "slug"), null);
            case "test" -> acts.test(new Actions.Draft().trigger(Json.str(a, "trigger")).code(Json.str(a, "code")).eventId(Json.str(a, "eventId")));
            case "testDeployed" -> acts.test(new Actions.Draft().slug(Json.str(a, "slug")).event(a.get("event")));
            case "dryRun" -> acts.dryRun(new Actions.Draft().trigger(Json.str(a, "trigger")).code(Json.str(a, "code")).replaces(Json.str(a, "replaces"))
                    .limit(Json.integer(a, "limit")));
            case "events" -> acts.events(Json.str(a, "trigger"), Json.integer(a, "limit"));
            case "logs" -> acts.logs(Json.str(a, "slug"), Json.integer(a, "limit"), null);
            case "metrics" -> acts.metrics(Json.str(a, "slug"), Json.str(a, "window"));
            case "triggers" -> acts.triggers();
            case "templates" -> acts.templates();
            case "renderTemplate" -> acts.renderTemplate(Json.str(a, "id"), Json.str(a, "trigger"), a.get("params"));
            case "setSecret" -> acts.secrets().set(Json.str(a, "name"), Json.str(a, "value"));
            case "listSecrets" -> acts.secrets().list();
            case "deleteSecret" -> {
                acts.secrets().delete(Json.str(a, "name"));
                yield null;
            }
            case "delete" -> {
                acts.delete(Json.str(a, "slug"));
                yield null;
            }
            default -> throw new IllegalStateException("no mapping for " + name);
        };
    }

    @Test
    void actionsApiVectors() {
        TouchqueClient tq = api.client();
        for (JsonNode v : Support.fixture("actions-api-vectors.json").get("calls")) {
            String name = v.get("name").asText();
            JsonNode result = call(tq, name, v.get("args"));
            JsonNode last = api.lastCall();
            JsonNode want = v.get("request");
            assertEquals(want.get("method").asText(), last.get("method").asText(), name);
            assertEquals(want.get("path").asText(), last.get("path").asText(), name);
            String url = last.get("url").asText();
            ObjectNode query = Json.object();
            if (url.contains("?")) {
                for (String part : url.substring(url.indexOf('?') + 1).split("&")) {
                    String[] kv = part.split("=", 2);
                    query.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
                }
            }
            assertEquals(want.has("query") ? want.get("query") : Json.object(), query, name);
            String method = want.get("method").asText();
            if (!method.equals("GET") && !method.equals("DELETE")) assertEquals(want.has("body") ? want.get("body") : Json.object(), last.get("body"), name);
            if (v.get("expect") instanceof ObjectNode expect) {
                assertEquals(expect.get("deployed").asBoolean(), result.get("deployed").asBoolean(), name);
                assertEquals(expect.get("approval.required").asBoolean(), result.get("approval").get("required").asBoolean(), name);
            }
        }
    }

    @Test
    void looseningVersionWaitsForThePhone() {
        TouchqueClient tq = api.client();
        JsonNode res = tq.actions().deploy("silent-office", new Actions.DeployOptions().trigger("risk.check")
                .code("exports.onExecute = (e, api) => api.allowSilent(\"office\");").capabilities(List.of("allow_silent")));
        assertFalse(res.get("deployed").asBoolean());
        assertTrue(res.get("approval").get("required").asBoolean());
        api.post("/__test/approve-version", Map.of("slug", "silent-office", "number", 1));
        assertEquals(1, tq.actions().get("silent-office").get("action").get("activeVersion").asInt());
    }

    @Test
    void badInputIsRefusedBeforeAnyRequest() {
        TouchqueClient tq = api.client();
        assertThrows(TouchqueConfigException.class, () -> tq.actions().deploy("Bad Slug", new Actions.DeployOptions().trigger("login.request").code("x")));
        assertThrows(TouchqueConfigException.class, () -> tq.actions().deploy("no-code", new Actions.DeployOptions().trigger("login.request")));
        assertThrows(TouchqueConfigException.class, () -> tq.actions().secrets().set("lowercase", "v"));
        assertThrows(TouchqueConfigException.class, () -> tq.actions().renderTemplate("Bad-Id", "login.request", null));
        assertTrue(api.calls().isEmpty());
    }
}
