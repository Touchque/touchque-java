package com.touchque.resources;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.Destination;
import com.touchque.LoginDetail;
import com.touchque.SecurityChanges;
import com.touchque.TouchQueConfigException;
import com.touchque.internal.Json;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/** Every field of {@code POST /login/request}, with fluent setters. */
public final class LoginRequestOptions {
    private final String externalUsername;
    private String type = "LOGIN";
    private String referenceId;
    private String clientIp;
    private String userAgent;
    private boolean requireBiometric;
    private boolean requireNumberMatch;
    private Integer challengeDigits;
    private Integer expiresIn;
    private String clientSignals;
    private String deviceRisk;
    private String deviceRiskRequestId;
    private String qrPairing;
    private ObjectNode reply;
    private List<LoginDetail> details;
    private String browserProof;
    private Map<String, Object> context;
    private SecurityChanges securityChanges;
    private Destination destination;
    private String locale;
    private Duration timeout;
    private Duration pollInterval;
    private Consumer<Login.VerifyChallenge> onChallenge;

    /** @param externalUsername the user in YOUR system (email, id) */
    public LoginRequestOptions(String externalUsername) {
        this.externalUsername = externalUsername;
    }

    public String externalUsername() {
        return externalUsername;
    }

    /** The action type (default {@code LOGIN}). */
    public LoginRequestOptions type(String v) {
        this.type = v;
        return this;
    }

    public LoginRequestOptions referenceId(String v) {
        this.referenceId = v;
        return this;
    }

    /** The END USER's IP (shown as "City, Country" on the phone; Tor, travel and attack-tool checks). */
    public LoginRequestOptions clientIp(String v) {
        this.clientIp = v;
        return this;
    }

    /** The end user's User-Agent (shown as browser and device). */
    public LoginRequestOptions userAgent(String v) {
        this.userAgent = v;
        return this;
    }

    public LoginRequestOptions requireBiometric(boolean v) {
        this.requireBiometric = v;
        return this;
    }

    public LoginRequestOptions requireNumberMatch(boolean v) {
        this.requireNumberMatch = v;
        return this;
    }

    /** Digits of the matching number when one is shown: 2 or 3. The longer of this and the workspace policy wins. */
    public LoginRequestOptions challengeDigits(Integer v) {
        this.challengeDigits = v;
        return this;
    }

    /** How long the push waits for the person, in seconds: 30 (default) to 300. */
    public LoginRequestOptions expiresIn(Integer v) {
        this.expiresIn = v;
        return this;
    }

    /** The end user's page check from {@code @touchque/web}, passed through untouched: a browser driven by software asks with number matching. */
    public LoginRequestOptions clientSignals(String v) {
        this.clientSignals = v;
        return this;
    }

    /**
     * The page's device report from {@code @touchque/web} ({@code deviceRisk.collect({ purpose })}), passed
     * through untouched. Used only when your workspace turned Device risk on: its signals only ever ask
     * for more, and a device your admin marked "step up always" asks at once.
     */
    public LoginRequestOptions deviceRisk(String v) {
        this.deviceRisk = v;
        return this;
    }

    /** The page's identification ({@code deviceRisk.identify()}), preferred over deviceRisk; for this account only. */
    public LoginRequestOptions deviceRiskRequestId(String v) {
        this.deviceRiskRequestId = v;
        return this;
    }

    /**
     * A browser pairing by QR code ({@code tq.qrPairings()}), scanned and confirmed on the phone:
     * only the phone that scanned it is asked, once, with number matching, for the user it scanned for.
     */
    public LoginRequestOptions qrPairing(String v) {
        this.qrPairing = v;
        return this;
    }

    /**
     * Ask the person to type back on the phone a sign-in code another service sent them. {@code key}:
     * {@code CodeReply.newKey().publicKey()}; {@code channel} (sms, whatsapp, email, app, backup,
     * other) and {@code target} (the masked number or address, at most 40 characters) are shown on
     * the phone, null to leave out. {@code status().reply()} holds only the ciphertext:
     * {@code CodeReply.open} opens it. Such a request lives 5 minutes. Not with {@code qrPairing}.
     */
    public LoginRequestOptions reply(String key, String channel, String target) {
        ObjectNode r = Json.object().put("kind", "code").put("key", key);
        Json.put(r, "channel", channel);
        Json.put(r, "target", target);
        this.reply = r;
        return this;
    }

    /** Transaction context for the approval screen (at most 8 lines). */
    public LoginRequestOptions details(List<LoginDetail> v) {
        this.details = v;
        return this;
    }

    /**
     * Silent sign-ins: the browser's device-bound key proof exactly as the browser sent it
     * ({@code X-TouchQue-Browser}). Once the user approves this request, TouchQue knows the browser.
     */
    public LoginRequestOptions browserProof(String v) {
        this.browserProof = v;
        return this;
    }

    /** For your TouchQue Actions only ({@code event.context}); never shown on the phone. Any JSON object up to 4 KB. */
    public LoginRequestOptions context(Map<String, Object> v) {
        this.context = v;
        return this;
    }

    /** When the user's sign-in security last changed in your system. */
    public LoginRequestOptions securityChanges(SecurityChanges v) {
        this.securityChanges = v;
        return this;
    }

    /** Where the action sends money or value (shown in full on the phone; do not repeat it in details). */
    public LoginRequestOptions destination(Destination v) {
        this.destination = v;
        return this;
    }

    /** {@code tr} (default) or {@code en}: the language of the rows TouchQue adds. */
    public LoginRequestOptions locale(String v) {
        this.locale = v;
        return this;
    }

    /** verify() only: how long to wait (default 30 seconds). */
    public LoginRequestOptions timeout(Duration v) {
        this.timeout = v;
        return this;
    }

    /** verify() only: how often to ask (default 400 ms). */
    public LoginRequestOptions pollInterval(Duration v) {
        this.pollInterval = v;
        return this;
    }

    /**
     * verify() only: called once, right after the request is created and before any waiting.
     * Show {@code challengeCode} to the user now; the phone asks for it. Not called when only a
     * passkey can approve. An exception it throws is ignored.
     */
    public LoginRequestOptions onChallenge(Consumer<Login.VerifyChallenge> v) {
        this.onChallenge = v;
        return this;
    }

    Duration timeout() {
        return timeout;
    }

    Duration pollInterval() {
        return pollInterval;
    }

    Consumer<Login.VerifyChallenge> onChallenge() {
        return onChallenge;
    }

    /** The JSON body of the request. */
    public ObjectNode toJson() {
        return toJson(true);
    }

    ObjectNode toJson(boolean withWaitFields) {
        if (externalUsername == null || externalUsername.isEmpty()) throw new TouchQueConfigException("A login request needs the user (externalUsername)");
        ObjectNode body = Json.object();
        body.put("externalUsername", externalUsername);
        body.put("type", type == null || type.isEmpty() ? "LOGIN" : type);
        Json.put(body, "referenceId", referenceId);
        Json.put(body, "clientIp", clientIp);
        Json.put(body, "userAgent", userAgent);
        if (requireBiometric) body.put("requireBiometric", true);
        if (requireNumberMatch) body.put("requireNumberMatch", true);
        if (challengeDigits != null && (challengeDigits == 2 || challengeDigits == 3)) body.put("challengeDigits", challengeDigits);
        if (withWaitFields) {
            Json.put(body, "expiresIn", expiresIn);
            Json.put(body, "clientSignals", clientSignals);
        }
        Json.put(body, "qrPairing", qrPairing);
        if (reply != null) body.set("reply", reply.deepCopy());
        Json.put(body, "deviceRisk", deviceRisk);
        Json.put(body, "deviceRiskRequestId", deviceRiskRequestId);
        if (details != null && !details.isEmpty()) body.set("details", detailsJson(details));
        Json.put(body, "browserProof", browserProof);
        if (context != null && !context.isEmpty()) body.set("context", Json.toNode(context));
        if (securityChanges != null) Json.putNode(body, "securityChanges", securityChanges.toJson());
        if (destination != null) {
            ObjectNode d = Json.object().put("kind", destination.kind()).put("value", destination.value());
            if (destination.known() != null) d.set("known", Json.toNode(destination.known()));
            body.set("destination", d);
        }
        Json.put(body, "locale", locale);
        return body;
    }

    /** {@code [{label, value}, ...]}. */
    public static ArrayNode detailsJson(List<LoginDetail> details) {
        ArrayNode arr = Json.array();
        for (LoginDetail d : details) arr.add(Json.object().put("label", d.label()).put("value", d.value()));
        return arr;
    }
}
