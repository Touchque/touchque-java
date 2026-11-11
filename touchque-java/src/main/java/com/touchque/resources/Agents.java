package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.TouchqueApprovalMismatchException;
import com.touchque.TouchqueConfigException;
import com.touchque.crypto.ApprovalToken;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * AI agents as identities of their own: register an agent with its PUBLIC key, give it an
 * accountable owner and the action types it may ask approvals for, suspend, revoke or stop every
 * agent at once. The agent itself never gets your API key: it signs in with its own key
 * ({@link com.touchque.agents.TouchqueAgent}).
 *
 * <pre>{@code
 * var keys = AgentKeys.generate("ES256");                 // where the agent runs
 * var agent = tq.agents().create(new Agents.CreateOptions("Invoice bot", List.of("PAY_INVOICE")).publicKey(keys.publicJwk()));
 * }</pre>
 */
public final class Agents {
    private final TouchqueHttp http;
    private final Vault vault;
    private final Object jwksLock = new Object();
    private JsonNode jwks;
    private Instant jwksAt = Instant.EPOCH;
    private String audience;

    /** Internal: use {@code tq.agents()}. */
    public Agents(TouchqueHttp http) {
        this.http = http;
        this.vault = new Vault(http);
    }

    /** The token vault: people's tokens at other services, for your agents. */
    public Vault vault() {
        return vault;
    }

    /**
     * Uses an agent's approval exactly once, right before you execute: checks {@code expect} against
     * the token first (nothing is used on a mismatch), then Touchque checks the token and marks it
     * used, and the answer is checked again. Returns the approval (externalUsername, type, agent,
     * authorizationDetails, approvalProof, caseCode…).
     */
    public JsonNode redeemApproval(String token, ApprovalToken.Expectation expect) {
        ApprovalToken.assertMatches(ApprovalToken.decode(token).claims(), expect);
        JsonNode res = http.post("/agents/approvals/redeem", Json.object().put("token", token));
        JsonNode approval = res.get("approval") instanceof ObjectNode o ? o : Json.object();
        ObjectNode claims = Json.object();
        Json.put(claims, "sub", Json.str(approval, "externalUsername"));
        Json.put(claims, "type", Json.str(approval, "type"));
        if (approval.has("authorizationDetails")) claims.set("authorization_details", approval.get("authorizationDetails").deepCopy());
        ApprovalToken.assertMatches(claims, expect);
        return approval;
    }

    /**
     * The {@code aud} of this workspace's approval tokens ({@code touchque:workspace:<id>}), from
     * GET /agents/approval-audience; asked once, then kept.
     */
    public String approvalAudience() {
        synchronized (jwksLock) {
            if (audience == null) {
                String own = Json.str(http.get("/agents/approval-audience"), "audience");
                if (own == null || own.isEmpty()) throw new TouchqueApprovalMismatchException("Touchque did not name this workspace's approval audience");
                audience = own;
            }
            return audience;
        }
    }

    /**
     * Verifies an approval token offline (Touchque's published keys, expiry, {@code aud},
     * {@code expect}) and returns its claims. {@code aud} must be this workspace's: a null or empty
     * {@code audience} means {@link #approvalAudience()}, and a token without aud or for another
     * workspace is refused. It does not make the token single-use: {@link #redeemApproval} does.
     */
    public JsonNode verifyApprovalToken(String token, String audience, ApprovalToken.Expectation expect) {
        if (audience == null || audience.isEmpty()) audience = approvalAudience();
        try {
            return ApprovalToken.verifyWith(token, jwks(false), audience, expect);
        } catch (TouchqueApprovalMismatchException e) {
            if (!String.valueOf(e.getMessage()).contains("unknown key")) throw e;
            return ApprovalToken.verifyWith(token, jwks(true), audience, expect);
        }
    }

    private JsonNode jwks(boolean force) {
        synchronized (jwksLock) {
            if (force || jwks == null || Duration.between(jwksAt, Instant.now()).toMinutes() >= 5) {
                jwks = http.get("/agents/jwks.json");
                jwksAt = Instant.now();
            }
            return jwks;
        }
    }

    /** Refuses a private key before it leaves this process. */
    private static JsonNode publicOnly(JsonNode jwk) {
        if (jwk.has("d")) {
            throw new TouchqueConfigException("Pass the agent's PUBLIC key: this one has private parts (d). The private key must stay where the agent runs.");
        }
        return jwk.deepCopy();
    }

    /** A new agent's registration. */
    public static final class CreateOptions {
        private final String name;
        private final List<String> allowedTypes;
        private JsonNode publicKey;
        private List<JsonNode> publicKeys;
        private String description;
        private String ownerEmail;
        private String platform;
        private Integer reviewInDays;

        public CreateOptions(String name, List<String> allowedTypes) {
            this.name = name;
            this.allowedTypes = allowedTypes;
        }

        public CreateOptions publicKey(JsonNode v) {
            this.publicKey = v;
            return this;
        }

        public CreateOptions publicKeys(List<JsonNode> v) {
            this.publicKeys = v;
            return this;
        }

        public CreateOptions description(String v) {
            this.description = v;
            return this;
        }

        /** The accountable member (default: the API key's creator); the agent stops when they leave. */
        public CreateOptions ownerEmail(String v) {
            this.ownerEmail = v;
            return this;
        }

        /** e.g. openai-agents, claude-agent-sdk, langgraph. */
        public CreateOptions platform(String v) {
            this.platform = v;
            return this;
        }

        /** 1-365 (default 90). */
        public CreateOptions reviewInDays(Integer v) {
            this.reviewInDays = v;
            return this;
        }
    }

    /** Registers an agent (needs the agents:write scope). Returns the agent. */
    public JsonNode create(CreateOptions o) {
        ObjectNode body = Json.object().put("name", o.name);
        body.set("allowedTypes", Json.toNode(o.allowedTypes));
        Json.put(body, "description", o.description);
        Json.put(body, "ownerEmail", o.ownerEmail);
        Json.put(body, "platform", o.platform);
        Json.put(body, "reviewInDays", o.reviewInDays);
        if (o.publicKey != null) body.set("publicKey", publicOnly(o.publicKey));
        if (o.publicKeys != null) {
            ArrayNode keys = body.putArray("publicKeys");
            o.publicKeys.forEach(k -> keys.add(publicOnly(k)));
        }
        return agent(http.post("/agents", body));
    }

    /** The agents (optionally by status: active, suspended, revoked) and the kill switch: {@code {agents, killSwitch}}. */
    public JsonNode list(String status) {
        Map<String, Object> q = new HashMap<>();
        if (status != null && !status.isEmpty()) q.put("status", status);
        return http.get("/agents", q);
    }

    public JsonNode get(String agentId) {
        return agent(http.get(path(agentId)));
    }

    /**
     * Changes, hands over (ownerEmail) or renews (reviewInDays) an agent. {@code changes}: a Map or
     * record with name, description, ownerEmail, platform, allowedTypes, reviewInDays (nulls left out).
     */
    public JsonNode update(String agentId, Object changes) {
        return agent(http.patch(path(agentId), Json.toNodeWithoutNulls(changes)));
    }

    /** Adds a key (rotation: add the new one, move the agent to it, then remove the old one). */
    public JsonNode addKey(String agentId, JsonNode publicKey) {
        ObjectNode body = Json.object();
        body.set("publicKey", publicOnly(publicKey));
        return agent(http.post(path(agentId) + "/keys", body));
    }

    /** Removes a key; tokens the agent got with it stop at once. */
    public JsonNode removeKey(String agentId, String kid) {
        return agent(http.delete(path(agentId) + "/keys/" + TouchqueHttp.seg(kid)));
    }

    /** Stops an agent at once (its tokens too) until resumed. */
    public JsonNode suspend(String agentId, String reason) {
        return agent(http.post(path(agentId) + "/suspend", Json.put(Json.object(), "reason", reason)));
    }

    public JsonNode resume(String agentId) {
        return agent(http.post(path(agentId) + "/resume", Json.object()));
    }

    /** Revokes an agent for good (the record stays for the audit trail). */
    public JsonNode revoke(String agentId) {
        return agent(http.delete(path(agentId)));
    }

    /**
     * Sets the agent's budgets, amounts, recipients and background rule (a full replacement; left-out
     * fields take the defaults). {@code policy}: a Map or record with requestsPer10Min,
     * requestsPerUserPer10Min, amountPerRequest, amountPerDay ({@code {TRY: "1000.00"}}), background
     * (non_critical | never), newRecipients (ask | deny), recipientAllowlist, fourEyes
     * ({@code {approvers, above, types}}), requirePasskeyAbove.
     */
    public JsonNode setPolicy(String agentId, Object policy) {
        ObjectNode body = Json.object();
        body.set("policy", Json.toNodeWithoutNulls(policy));
        return agent(http.put(path(agentId) + "/policy", body));
    }

    /**
     * The workspace's agent events for a SIEM, oldest first: {@code {events, next, hasMore}}. Keep
     * {@code next} and pass it as {@code after}; the first call reads from {@code since} (ISO 8601;
     * default the last 24 hours).
     */
    public JsonNode listEvents(String after, String since, Integer limit) {
        Map<String, Object> q = new HashMap<>();
        q.put("after", after);
        q.put("since", since);
        q.put("limit", limit);
        return http.get("/agents/events", q);
    }

    /** The workspace's policy: every agent's floor (an agent's own policy can only make it stricter). */
    public JsonNode getWorkspacePolicy() {
        JsonNode p = http.get("/agents/workspace-policy").get("policy");
        return p != null ? p : Json.object();
    }

    /** Sets the workspace's policy (a full replacement; a field left out sets no floor). Same fields as {@link #setPolicy}. */
    public JsonNode setWorkspacePolicy(Object policy) {
        ObjectNode body = Json.object();
        body.set("policy", Json.toNodeWithoutNulls(policy));
        JsonNode p = http.put("/agents/workspace-policy", body).get("policy");
        return p != null ? p : Json.object();
    }

    /** The people who stopped this agent asking them (reason not_me, coached, rejections or phone): the {@code blocks} array. */
    public JsonNode listBlocks(String agentId) {
        return Actions.field(http.get(path(agentId) + "/blocks"), "blocks");
    }

    /** Lets the agent ask this person again (check with them first). */
    public void liftBlock(String agentId, String user) {
        http.delete(path(agentId) + "/blocks/" + TouchqueHttp.seg(user));
    }

    /** An agent's mandates, optionally one person's: the {@code mandates} array. */
    public JsonNode listMandates(String agentId, String user) {
        Map<String, Object> q = new HashMap<>();
        if (user != null && !user.isEmpty()) q.put("externalUsername", user);
        return Actions.field(http.get(path(agentId) + "/mandates", q), "mandates");
    }

    /** Ends an agent's mandate at once. */
    public JsonNode revokeMandate(String agentId, String mandateId) {
        JsonNode res = http.post(path(agentId) + "/mandates/" + TouchqueHttp.seg(mandateId) + "/revoke", Json.object());
        return res.has("mandate") ? res.get("mandate") : res;
    }

    /** Stops (true) or restarts (false) every agent of the workspace at once. */
    public JsonNode setKillSwitch(boolean engaged, String reason) {
        ObjectNode body = Json.object().put("engaged", engaged);
        Json.put(body, "reason", reason);
        return http.put("/agents/kill-switch", body).get("killSwitch");
    }

    private static String path(String agentId) {
        return "/agents/" + TouchqueHttp.seg(agentId);
    }

    private static JsonNode agent(JsonNode res) {
        return res.get("agent");
    }

    /**
     * The token vault for your agents: after your own OAuth flow with a person, deposit their tokens;
     * Touchque keeps them sealed and refreshes them, and the agents a connection names get a
     * short-lived access token ({@code TouchqueAgent.getConnectionToken}), never the refresh token.
     */
    public static final class Vault {
        private final TouchqueHttp http;

        Vault(TouchqueHttp http) {
            this.http = http;
        }

        /** The {@code connections} array. */
        public JsonNode listConnections() {
            return Actions.field(http.get("/agents/vault/connections"), "connections");
        }

        /**
         * Adds or replaces a connection; the client secret is kept when left out of a replacement.
         * {@code provider}: google, microsoft, github, facebook, linkedin, x or oidc. {@code agentIds}:
         * the agents that may get tokens of this connection.
         */
        public JsonNode putConnection(String name, String provider, String clientId, String clientSecret, String tenant, String issuer, List<String> agentIds) {
            ObjectNode body = Json.object().put("provider", provider).put("clientId", clientId);
            Json.put(body, "clientSecret", clientSecret);
            Json.put(body, "tenant", tenant);
            Json.put(body, "issuer", issuer);
            if (agentIds != null) body.set("agentIds", Json.toNode(agentIds));
            return http.put("/agents/vault/connections/" + TouchqueHttp.seg(name), body).get("connection");
        }

        /** Removes it, and every person's tokens kept for it. */
        public JsonNode removeConnection(String name) {
            return http.delete("/agents/vault/connections/" + TouchqueHttp.seg(name));
        }

        /** Keeps a person's tokens (replacing earlier ones) after your own OAuth flow with them. */
        public JsonNode deposit(String connection, String user, String accessToken, String refreshToken, Integer expiresIn, String scope) {
            ObjectNode body = Json.object().put("accessToken", accessToken);
            Json.put(body, "refreshToken", refreshToken);
            Json.put(body, "expiresIn", expiresIn);
            Json.put(body, "scope", scope);
            return http.put("/agents/vault/accounts/" + TouchqueHttp.seg(connection) + "/" + TouchqueHttp.seg(user), body).get("account");
        }

        /** A person's accounts in the vault (never a token): the {@code accounts} array. */
        public JsonNode listAccounts(String user) {
            return Actions.field(http.get("/agents/vault/accounts", Map.of("externalUsername", user)), "accounts");
        }

        /** Deletes a person's tokens: agents get nothing more for them there. */
        public void removeAccount(String connection, String user) {
            http.delete("/agents/vault/accounts/" + TouchqueHttp.seg(connection) + "/" + TouchqueHttp.seg(user));
        }
    }
}
