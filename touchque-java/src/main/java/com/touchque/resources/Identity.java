package com.touchque.resources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Json;
import com.touchque.internal.TouchqueHttp;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Touchque Login Management API: your customers' accounts, roles, business-customer organizations,
 * apps, APIs, connections and the tenant itself, from your server with your workspace key. Bodies
 * and queries are any object (a Map, a record, a JsonNode) with the API's camelCase fields; answers
 * are the API's JSON.
 *
 * <pre>{@code
 * var found = tq.identity().users().list(Map.of("q", "ayse"));
 * tq.identity().users().block(userId, "chargeback");
 * }</pre>
 */
public final class Identity {
    private final TouchqueHttp http;
    private final Users users;
    private final Jobs imports;
    private final Jobs exports;
    private final Crud roles;
    private final Organizations organizations;
    private final Clients clients;
    private final Crud apis;
    private final Crud connections;
    private final Crud customDomains;

    /** Internal: use {@code tq.identity()}. */
    public Identity(TouchqueHttp http) {
        this.http = http;
        this.users = new Users(http);
        this.imports = new Jobs(http, "imports");
        this.exports = new Jobs(http, "exports");
        this.roles = new Crud(http, "/identity/roles", "roles");
        this.organizations = new Organizations(http);
        this.clients = new Clients(http);
        this.apis = new Crud(http, "/identity/apis", "apis");
        this.connections = new Crud(http, "/identity/connections", "connections");
        this.customDomains = new Crud(http, "/identity/custom-domains", "domains");
    }

    public Users users() {
        return users;
    }

    public Jobs imports() {
        return imports;
    }

    public Jobs exports() {
        return exports;
    }

    public Crud roles() {
        return roles;
    }

    public Organizations organizations() {
        return organizations;
    }

    public Clients clients() {
        return clients;
    }

    public Crud apis() {
        return apis;
    }

    public Crud connections() {
        return connections;
    }

    public Crud customDomains() {
        return customDomains;
    }

    /** The tenant (404 not_enabled until it is set up). */
    public JsonNode getTenant() {
        return http.get("/identity/tenant");
    }

    /** Turns Touchque Login on (slug, displayName) or changes its settings. */
    public JsonNode updateTenant(Object body) {
        return http.put("/identity/tenant", Json.toNode(body));
    }

    /** Retires the tenant's signing key and makes a new one active. */
    public JsonNode rotateSigningKey() {
        return http.post("/identity/tenant/signing-keys/rotate", Json.object());
    }

    /**
     * The phone app the hosted pages tell customers to approve on ("Approve on the Acme app"). null:
     * your brand name when the Mobile SDK is set up, else Touchque ({@code approverApp} in the tenant shows which).
     */
    public JsonNode setApproverAppName(String name) {
        ObjectNode branding = Json.object();
        if (name == null) branding.putNull("approverAppName");
        else branding.put("approverAppName", name);
        ObjectNode body = Json.object();
        body.set("branding", branding);
        return http.put("/identity/tenant", body);
    }

    /**
     * Serve sign-in only on the primary custom domain: {slug}.login.touchque.com redirects page loads
     * there and refuses other calls. Turning it on needs a verified primary domain with a working certificate.
     */
    public JsonNode setCustomDomainOnly(boolean on) {
        return http.put("/identity/tenant", Json.object().put("customDomainOnly", on));
    }

    /** Checks a verified custom domain's certificate at the sign-in edge now ({@code certificate}: pending | active | error). */
    public JsonNode checkDomainCertificate(String domainId) {
        return http.post("/identity/custom-domains/" + TouchqueHttp.seg(domainId) + "/check-certificate", Json.object());
    }

    /** The delivery log. Message text only in the local dev inbox. */
    public JsonNode outbox(Object query) {
        return http.get("/identity/outbox", query(query));
    }

    /** Wrong passwords, suspicious addresses, bot challenge, breached passwords, new-browser notices, the risk engine. */
    public JsonNode getAttackProtection() {
        return http.get("/identity/attack-protection");
    }

    /** Partial; the bot challenge's secret is write-only. */
    public JsonNode setAttackProtection(Object settings) {
        return http.put("/identity/attack-protection", Json.toNode(settings));
    }

    /** What attack protection caught lately. */
    public JsonNode attackEvents(Object query) {
        return http.get("/identity/attack-protection/events", query(query));
    }

    /** The email and SMS providers; secrets never come back ({@code secretsSet}). */
    public JsonNode getDelivery() {
        return http.get("/identity/delivery");
    }

    /**
     * Your own provider: email smtp, ses, postmark, sendgrid; sms twilio, netgsm, e.g.
     * {@code Map.of("provider", "postmark", "from", "login@acme.com", "serverToken", token)}. A secret
     * left out keeps its stored value.
     */
    public JsonNode setDelivery(String channel, Object provider) {
        return http.put("/identity/delivery/" + TouchqueHttp.seg(channel), Json.toNode(provider));
    }

    /** Back to Touchque's transport. */
    public JsonNode removeDelivery(String channel) {
        return http.delete("/identity/delivery/" + TouchqueHttp.seg(channel));
    }

    /** One test message through the provider in use. */
    public JsonNode testDelivery(String channel, String to) {
        return http.post("/identity/delivery/" + TouchqueHttp.seg(channel) + "/test", Json.object().put("to", to));
    }

    /** A query from any object: its fields as strings (booleans lower-case), nulls left out. */
    static Map<String, Object> query(Object query) {
        if (query == null) return null;
        JsonNode node = Json.toNode(query);
        Map<String, Object> out = new HashMap<>();
        if (node == null || !node.isObject()) return out;
        Iterator<Map.Entry<String, JsonNode>> it = node.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            JsonNode v = e.getValue();
            if (v == null || v.isNull()) continue;
            out.put(e.getKey(), v.isTextual() ? v.textValue() : v.isBoolean() ? (v.booleanValue() ? "true" : "false") : v.toString());
        }
        return out;
    }

    /** List, get, create, update and delete for one kind of Touchque Login object. */
    public static class Crud {
        protected final TouchqueHttp http;
        protected final String base;
        private final String listKey;

        Crud(TouchqueHttp http, String base, String listKey) {
            this.http = http;
            this.base = base;
            this.listKey = listKey;
        }

        /** The objects (an array). */
        public JsonNode list(Object query) {
            return Actions.field(http.get(base, Identity.query(query)), listKey);
        }

        public JsonNode list() {
            return list(null);
        }

        public JsonNode get(String id) {
            return http.get(base + "/" + TouchqueHttp.seg(id));
        }

        public JsonNode create(Object body) {
            return http.post(base, Json.toNode(body));
        }

        public JsonNode update(String id, Object body) {
            return http.patch(base + "/" + TouchqueHttp.seg(id), Json.toNode(body));
        }

        public JsonNode delete(String id) {
            return http.delete(base + "/" + TouchqueHttp.seg(id));
        }
    }

    /** Business customers, their members and invitations. */
    public static final class Organizations extends Crud {
        Organizations(TouchqueHttp http) {
            super(http, "/identity/organizations", "organizations");
        }

        public JsonNode members(String orgId) {
            return http.get(org(orgId) + "/members");
        }

        public JsonNode addMembers(String orgId, List<String> userIds) {
            ObjectNode body = Json.object();
            body.set("userIds", Json.toNode(userIds));
            return http.post(org(orgId) + "/members", body);
        }

        public JsonNode removeMember(String orgId, String userId) {
            return http.delete(org(orgId) + "/members/" + TouchqueHttp.seg(userId));
        }

        public JsonNode setConnections(String orgId, Object connections) {
            ObjectNode body = Json.object();
            body.set("connections", Json.toNode(connections));
            return http.put(org(orgId) + "/connections", body);
        }

        public JsonNode invitations(String orgId) {
            return http.get(org(orgId) + "/invitations");
        }

        /** The link opens the app's sign-in route (initiateLoginUri) with organization and invitation. */
        public JsonNode invite(String orgId, Object invitation) {
            return http.post(org(orgId) + "/invitations", Json.toNode(invitation));
        }

        public JsonNode revokeInvitation(String orgId, String invitationId) {
            return http.delete(org(orgId) + "/invitations/" + TouchqueHttp.seg(invitationId));
        }

        private String org(String orgId) {
            return base + "/" + TouchqueHttp.seg(orgId);
        }
    }

    /** Your customers' apps (OpenID Connect clients). */
    public static final class Clients extends Crud {
        Clients(TouchqueHttp http) {
            super(http, "/identity/clients", "clients");
        }

        /** A new client secret: it is in the answer ({@code clientSecret}), this once; the old one stops working. */
        public JsonNode rotateSecret(String clientId) {
            return http.post(base + "/" + TouchqueHttp.seg(clientId) + "/rotate-secret", Json.object());
        }
    }

    /** Bulk user imports and exports, running in the background. */
    public static final class Jobs {
        private final TouchqueHttp http;
        private final String kind;

        Jobs(TouchqueHttp http, String kind) {
            this.http = http;
            this.kind = kind;
        }

        /** Imports: {@code {users, upsert}}; exports: {@code {format: "csv" | "json"}}. */
        public JsonNode start(Object body) {
            return http.post("/identity/users-" + kind, Json.toNode(body));
        }

        public JsonNode get(String jobId) {
            return http.get("/identity/users-" + kind + "/" + TouchqueHttp.seg(jobId));
        }

        /** Exports: the finished file (CSV or JSON lines), as text. */
        public String file(String jobId) {
            return http.getText("/identity/users-" + kind + "/" + TouchqueHttp.seg(jobId) + "/file");
        }

        /** Polls until the job is done or failed (or the timeout passes: the last state). Nulls: every second, ten minutes. */
        public JsonNode waitFor(String jobId, Duration interval, Duration timeout) {
            Instant end = Instant.now().plus(timeout != null ? timeout : Duration.ofMinutes(10));
            while (true) {
                JsonNode job = get(jobId);
                if (!"running".equals(Json.str(job, "status")) || Instant.now().isAfter(end)) return job;
                Login.sleep(interval != null ? interval : Duration.ofSeconds(1));
            }
        }
    }

    /** A tenant's customer accounts. */
    public static final class Users {
        private final TouchqueHttp http;

        Users(TouchqueHttp http) {
            this.http = http;
        }

        private static String u(String userId) {
            return "/identity/users/" + TouchqueHttp.seg(userId);
        }

        /** Query fields: q, blocked, emailVerified, connection, organization, limit, cursor. */
        public JsonNode list(Object query) {
            return http.get("/identity/users", query(query));
        }

        public JsonNode get(String userId) {
            return http.get(u(userId));
        }

        /**
         * email and: password, passwordHash (bcrypt/argon2), customPasswordHash, emailVerified, name,
         * givenName, familyName, phone, locale, userMetadata, appMetadata, sendVerificationEmail.
         */
        public JsonNode create(Object user) {
            return http.post("/identity/users", Json.toNode(user));
        }

        /** Metadata is merged; a key set to null is removed (null values are kept in the body). */
        public JsonNode update(String userId, Object changes) {
            return http.patch(u(userId), Json.toNode(changes));
        }

        /** Erasure (KVKK/GDPR): the account and every workspace row that names it. */
        public JsonNode delete(String userId) {
            return http.delete(u(userId));
        }

        public JsonNode block(String userId, String reason) {
            return http.post(u(userId) + "/block", Json.put(Json.object(), "reason", reason));
        }

        public JsonNode unblock(String userId) {
            return http.post(u(userId) + "/unblock", Json.object());
        }

        /** Everything about the person (KVKK/GDPR access request); never hashes. */
        public JsonNode export(String userId) {
            return http.get(u(userId) + "/export");
        }

        public JsonNode sessions(String userId) {
            return http.get(u(userId) + "/sessions");
        }

        /** Signs the person out of one session (the others stay). */
        public JsonNode endSession(String userId, String sessionId) {
            return http.delete(u(userId) + "/sessions/" + TouchqueHttp.seg(sessionId));
        }

        public JsonNode signOutEverywhere(String userId) {
            return http.delete(u(userId) + "/sessions");
        }

        /** Removes passkeys, unlinks the Touchque app, turns email codes off, signs out everywhere. */
        public JsonNode resetMfa(String userId) {
            return http.delete(u(userId) + "/mfa");
        }

        /** Accounts at providers whose tokens the vault keeps for the user (connections with tokenVault on). */
        public JsonNode connectedAccounts(String userId) {
            return http.get(u(userId) + "/connected-accounts");
        }

        /** Deletes the stored tokens: apps stop using the account for the user; signing in with it stays. */
        public JsonNode disconnectAccount(String userId, String accountId) {
            return http.delete(u(userId) + "/connected-accounts/" + TouchqueHttp.seg(accountId));
        }

        public JsonNode unlinkIdentity(String userId, String identityId, boolean force) {
            return http.delete(u(userId) + "/identities/" + TouchqueHttp.seg(identityId) + (force ? "?force=true" : ""));
        }

        public JsonNode sendVerificationEmail(String userId, String returnTo) {
            return http.post(u(userId) + "/verification-email", Json.put(Json.object(), "returnTo", returnTo));
        }

        /** {@code sendEmail} false: the link comes back for you to deliver. */
        public JsonNode passwordReset(String userId, boolean sendEmail, Integer ttlSec) {
            ObjectNode body = Json.object().put("sendEmail", sendEmail);
            Json.put(body, "ttlSec", ttlSec);
            return http.post(u(userId) + "/password-reset", body);
        }

        public JsonNode roles(String userId) {
            return http.get(u(userId) + "/roles");
        }

        public JsonNode addRoles(String userId, List<String> roleIds, String organizationId) {
            ObjectNode body = Json.object();
            body.set("roleIds", Json.toNode(roleIds));
            Json.put(body, "organizationId", organizationId);
            return http.post(u(userId) + "/roles", body);
        }

        public JsonNode removeRole(String userId, String roleId, String organizationId) {
            return http.delete(u(userId) + "/roles/" + TouchqueHttp.seg(roleId) + (organizationId == null ? "" : "?organizationId=" + TouchqueHttp.seg(organizationId)));
        }

        public JsonNode logs(String userId, Integer limit) {
            Map<String, Object> q = new HashMap<>();
            q.put("limit", limit);
            return http.get(u(userId) + "/logs", q);
        }
    }
}
