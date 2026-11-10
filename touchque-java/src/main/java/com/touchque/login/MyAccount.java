package com.touchque.login;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.internal.Json;
import com.touchque.internal.TouchQueHttp;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;

/**
 * The TouchQue Login My Account API (/me/v1) from your server: the signed-in customer's own
 * profile, sign-in methods, devices, apps and data, called with their access token for audience
 * https://&lt;domain&gt;/me/. Security changes, the data export and deletion need a recent
 * sign-in; when it is too old a {@link MyAccountException} with {@link MyAccountException#isStepUp()}
 * is thrown.
 *
 * <pre>{@code
 * var me = login.myAccountToken(refreshToken, "read:me update:me");   // keep me.refreshToken()
 * var account = login.myAccount(me.accessToken());
 * JsonNode profile = account.get().get("profile");
 * }</pre>
 */
public final class MyAccount {
    private final String issuer;
    private final String accessToken;
    private final HttpClient client;

    public MyAccount(String domain, String accessToken, HttpClient httpClient) {
        if (domain == null || domain.isEmpty() || accessToken == null || accessToken.isEmpty()) {
            throw new MyAccountException("config", 0, "domain and accessToken are required", null);
        }
        this.issuer = HostedLogin.issuerOf(domain);
        this.accessToken = accessToken;
        this.client = httpClient != null ? httpClient : HostedLogin.SHARED_CLIENT;
    }

    public MyAccount(String domain, String accessToken) {
        this(domain, accessToken, null);
    }

    /** The hosted account page, optionally at security, devices or privacy. */
    public String accountPageUrl(String section) {
        return issuer + "/account" + (section == null || section.isEmpty() ? "" : "/" + section);
    }

    private ObjectNode call(String method, String path, JsonNode body) {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(issuer + "/me/v1" + path)).header("Authorization", "Bearer " + accessToken);
        if (body != null) {
            req.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(Json.write(body), StandardCharsets.UTF_8));
        } else {
            req.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HostedLogin.Answer res;
        try {
            res = HostedLogin.send(client, req);
        } catch (HostedLoginException e) {
            throw new MyAccountException("network_error", 0, e.description(), null);
        }
        if (res.status() == 204) return Json.object();
        ObjectNode d = Json.parseObject(res.body());
        if (res.status() >= 400) {
            String err = Json.str(d, "error");
            throw new MyAccountException(err != null ? err : "http_" + res.status(), res.status(), Json.str(d, "error_description"), Json.integer(d, "max_age"));
        }
        return d;
    }

    private static String seg(String v) {
        return TouchQueHttp.seg(v);
    }

    public ObjectNode get() {
        return call("GET", "", null);
    }

    public ObjectNode getProfile() {
        return call("GET", "/profile", null);
    }

    /** name, givenName, familyName, nickname, locale, userMetadata (merged; null removes a key). A Map, record or JsonNode. */
    public ObjectNode updateProfile(Object changes) {
        return call("PATCH", "/profile", Json.toNode(changes));
    }

    public ObjectNode authenticationMethods() {
        return call("GET", "/authentication-methods", null);
    }

    public void renamePasskey(String id, String label) {
        call("PATCH", "/authentication-methods/passkeys/" + seg(id), Json.object().put("label", label));
    }

    /** Needs a recent sign-in. */
    public void removePasskey(String id) {
        call("DELETE", "/authentication-methods/passkeys/" + seg(id), null);
    }

    /** Needs a recent sign-in. */
    public void unlinkTouchQueApp() {
        call("DELETE", "/authentication-methods/touchque", null);
    }

    /** Email codes as a second step. Needs a recent sign-in. */
    public ObjectNode setEmailCodes(boolean enabled) {
        return call("PUT", "/authentication-methods/email", Json.object().put("enabled", enabled));
    }

    /** Texts a code to a new number for text-message codes. Needs a recent sign-in. */
    public ObjectNode startSmsEnrollment(String phone) {
        return call("POST", "/authentication-methods/sms", Json.object().put("phone", phone));
    }

    /** The code from that text: text-message codes are on. Needs a recent sign-in. */
    public ObjectNode verifySmsEnrollment(String code) {
        return call("POST", "/authentication-methods/sms/verify", Json.object().put("code", code));
    }

    /** Needs a recent sign-in. */
    public void removeSmsCodes() {
        call("DELETE", "/authentication-methods/sms", null);
    }

    /** Needs a recent sign-in. */
    public void unlinkIdentity(String id) {
        call("DELETE", "/identities/" + seg(id), null);
    }

    /** Apps stop using a linked account for the person (token vault: the identity's appAccess id); signing in with it stays. */
    public void stopAppAccess(String id) {
        call("DELETE", "/app-access/" + seg(id), null);
    }

    /** Sets or changes the password; other sessions end. Needs a recent sign-in. */
    public ObjectNode setPassword(String password) {
        return call("PUT", "/password", Json.object().put("password", password));
    }

    /** Needs a recent sign-in and another way to sign in. */
    public void removePassword() {
        call("DELETE", "/password", null);
    }

    /** A confirmation link goes to the new address. Needs a recent sign-in. */
    public ObjectNode changeEmail(String email) {
        return call("POST", "/email", Json.object().put("email", email));
    }

    public ObjectNode sendVerificationEmail() {
        return call("POST", "/email/verification", null);
    }

    public ObjectNode sessions() {
        return call("GET", "/sessions", null);
    }

    public void endSession(String id) {
        call("DELETE", "/sessions/" + seg(id), null);
    }

    public ObjectNode endOtherSessions() {
        return call("DELETE", "/sessions", null);
    }

    public ObjectNode apps() {
        return call("GET", "/apps", null);
    }

    public ObjectNode revokeApp(String clientId) {
        return call("DELETE", "/apps/" + seg(clientId), null);
    }

    public ObjectNode consents() {
        return call("GET", "/consents", null);
    }

    public ObjectNode setMarketing(boolean granted) {
        return call("PUT", "/consents/marketing", Json.object().put("granted", granted));
    }

    /** Everything about the person (KVKK/GDPR). Needs a recent sign-in. */
    public ObjectNode exportData() {
        return call("GET", "/export", null);
    }

    /** Erases the account at once. Needs delete:me and a recent sign-in. */
    public ObjectNode deleteAccount() {
        return call("DELETE", "", null);
    }
}
