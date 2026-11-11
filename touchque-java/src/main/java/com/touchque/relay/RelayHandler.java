package com.touchque.relay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.LoginDetail;
import com.touchque.TouchqueApiException;
import com.touchque.TouchqueClient;
import com.touchque.TouchquePasskeyRequiredException;
import com.touchque.TouchqueRejectedException;
import com.touchque.TouchqueTimeoutException;
import com.touchque.flow.Approval;
import com.touchque.flow.Guard;
import com.touchque.internal.Json;
import com.touchque.internal.SdkLog;
import com.touchque.resources.Offline;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

/**
 * Framework-agnostic relay: the routes a frontend ({@code @touchque/web}) needs for push 2FA,
 * offline codes and passkeys, so you don't hand-write them. Same routes and behaviour as the Node
 * SDK's {@code touchqueRouter}:
 * <pre>
 * POST   /enroll/start                  (signed in)   generateSecret response
 * GET    /enroll/status                 (signed in)   { linked, used, deviceId }
 * POST   /login                         (pre-auth)    202 { touchque: step, token } until approved
 * POST   /offline/challenge             (pre-auth)    QR for a phone with no internet
 * POST   /offline/verify                (pre-auth)    body.challengeId / code
 * POST   /offline/totp                  (pre-auth)    the time-based code
 * POST   /passkey/authenticate/options  (pre-auth)    body.email; none = any passkey (autofill)
 * POST   /passkey/authenticate/verify   (pre-auth)    body.attemptId / response
 * POST   /passkey/login/options         (pre-auth)    body.requestId: approve a pending request
 * POST   /passkey/login/verify          (pre-auth)    body.requestId / response
 * POST   /passkey/register/options      (signed in)   the phone approves adding a passkey first
 * POST   /passkey/register/verify       (signed in)
 * GET    /passkey/credentials           (signed in)
 * DELETE /passkey/credentials/{id}      (signed in)
 * </pre>
 */
public final class RelayHandler<T> {
    /** A 1.5 s poll for a 2-minute push is 80 requests: one attempt's worth of polls. */
    private static final int POLLS_PER_ATTEMPT = 10;
    /** Reserved action: the approval on the phone that unlocks adding a passkey. */
    private static final String PASSKEY_ENROLL_ACTION = "PASSKEY_ENROLL";

    private final TouchqueClient tq;
    private final RelayOptions<T> o;
    private final RateLimit.Limiter limiter;
    private final boolean offlineEnabled;

    public RelayHandler(TouchqueClient client, RelayOptions<T> options) {
        this.tq = client;
        this.o = options;
        this.limiter = options.rateLimit == null ? null : new RateLimit.Limiter(options.rateLimit);
        this.offlineEnabled = options.getLoginUser != null || options.allowOfflineWithoutFirstFactor;
        if (options.getLoginUser == null) {
            client.http().log().warn("[Touchque] RelayHandler: POST /login takes the username from the request body"
                    + (offlineEnabled ? ", and so do the offline routes" : "; the offline routes are disabled until you set it")
                    + ". Set getLoginUser to bind them to your first factor (password step) so they cannot be used against arbitrary users.");
        }
    }

    /** Handles one relay request; null when no relay route matches (answer 404 yourself). */
    public RelayResponse handle(RelayRequest<T> req) {
        String method = req.method().toUpperCase(Locale.ROOT);
        if (method.equals("HEAD")) method = "GET";
        String path = "/" + req.path().split("\\?", 2)[0].replaceAll("^/+|/+$", "");
        switch (method + " " + path.toLowerCase(Locale.ROOT)) {
            case "POST /enroll/start":
                return enrollStart(req);
            case "GET /enroll/status":
                return enrollStatus(req);
            case "POST /login":
                return login(req);
            case "POST /offline/challenge":
                return offlineChallenge(req);
            case "POST /offline/verify":
                return offlineVerify(req);
            case "POST /offline/totp":
                return offlineTotp(req);
            case "POST /passkey/authenticate/options":
                return passkeyAuthenticateOptions(req);
            case "POST /passkey/authenticate/verify":
                return passkeyAuthenticateVerify(req);
            case "POST /passkey/login/options":
                return passkeyLoginOptions(req);
            case "POST /passkey/login/verify":
                return passkeyLoginVerify(req);
            case "POST /passkey/register/options":
                return passkeyRegisterOptions(req);
            case "POST /passkey/register/verify":
                return passkeyRegisterVerify(req);
            case "GET /passkey/credentials":
                return passkeyCredentials(req);
            default:
                break;
        }
        String prefix = "/passkey/credentials/";
        if (method.equals("DELETE") && path.toLowerCase(Locale.ROOT).startsWith(prefix) && path.length() > prefix.length() && !path.substring(prefix.length()).contains("/")) {
            return deleteCredential(req, URLDecoder.decode(path.substring(prefix.length()).replace("+", "%2B"), StandardCharsets.UTF_8));
        }
        return null;
    }

    // ── push 2FA: enrollment ──────────────────────────────────────────────

    private RelayResponse enrollStart(RelayRequest<T> req) {
        String userId = userId(req);
        if (userId == null) return unauthorized();
        try {
            return new RelayResponse(200, tq.auth().generateSecret(userId));
        } catch (TouchqueApiException e) {
            if (e.status() != 409) return relayError(e);
            // 409: a QR was issued and not scanned yet (safe to issue a new one), or a phone is ALREADY
            // linked. Replacing a linked phone must never happen from a plain session: that is how an
            // attacker with a stolen password would swap in their own phone.
            try {
                JsonNode current = tq.auth().getUser(userId);
                if (Json.bool(current, "used") || !empty(Json.str(current, "deviceId"))) {
                    return new RelayResponse(409, Json.object().put("error", "already_linked").put("message", "A phone is already linked to this account."));
                }
                return new RelayResponse(200, tq.auth().resetSecret(userId));
            } catch (RuntimeException retry) {
                return relayError(retry);
            }
        } catch (RuntimeException e) {
            return relayError(e);
        }
    }

    private RelayResponse enrollStatus(RelayRequest<T> req) {
        String userId = userId(req);
        if (userId == null) return unauthorized();
        try {
            JsonNode u = tq.auth().getUser(userId);
            boolean used = Json.bool(u, "used");
            String deviceId = Json.str(u, "deviceId");
            ObjectNode body = Json.object().put("linked", used && !empty(deviceId)).put("used", used);
            if (deviceId == null) body.putNull("deviceId");
            else body.put("deviceId", deviceId);
            return new RelayResponse(200, body);
        } catch (TouchqueApiException e) {
            if (e.status() == 404) return new RelayResponse(200, Json.object().put("linked", false).put("used", false).putNull("deviceId"));
            return relayError(e);
        } catch (RuntimeException e) {
            return relayError(e);
        }
    }

    // ── push 2FA: login ───────────────────────────────────────────────────

    private RelayResponse login(RelayRequest<T> req) {
        Object[] lu = loginUser(req);
        if (lu[1] != null) return (RelayResponse) lu[1];
        String user = (String) lu[0];
        List<LoginDetail> details = o.getDetails == null ? null : o.getDetails.apply(req.nativeRequest());
        Guard.Input input = guardInput(req, user, o.actionType, details, o.getLoginUser != null, o.silentSignIn);
        // Polling an approval already sent is not a new attempt: its own, larger per-IP budget, never the user's push budget.
        RelayResponse limited = Guard.isStatusPoll(tq, input) ? allow(req, "login-poll", null, POLLS_PER_ATTEMPT) : allow(req, "login", user, 1);
        if (limited != null) return limited;
        Guard.Result result = Guard.run(tq, input);
        if (result.approved() == null) return guardResponse(result);
        Approval approved = result.approved();
        RelayResponse res = new RelayResponse(200);
        try {
            if (o.onAuthenticated != null) {
                String via = switch (String.valueOf(approved.confirmedVia())) {
                    case "OFFLINE_TOTP" -> "offline-totp";
                    case "OFFLINE_CODE" -> "offline";
                    case "SILENT" -> "silent";
                    default -> "login";
                };
                o.onAuthenticated.accept(req.nativeRequest(), res, new RelayAuthenticated(user, approved.requestId(), via));
            }
            ObjectNode body = Json.object().put("status", "success").put("requestId", approved.requestId());
            body.set("assurance", Json.toNode(approved.assurance()));
            return res.body(body);
        } catch (Exception e) {
            return authResultError(e);
        }
    }

    /** The guard input of a relay request (the guard headers read from it). */
    public static <T> Guard.Input guardInput(RelayRequest<T> req, String user, String action, List<LoginDetail> details, boolean enroll, Guard.SilentSignIn silent) {
        String offline = req.header().apply(Guard.OFFLINE_HEADER);
        String proof = silent == null ? null : req.header().apply(Guard.BROWSER_HEADER);
        return new Guard.Input(user, action).details(details).ip(req.ip() != null && !req.ip().isEmpty() ? req.ip() : null).userAgent(req.userAgent())
                .token(nonEmpty(req.header().apply(Guard.TOKEN_HEADER))).offline("1".equals(offline) || "true".equals(offline))
                .code(nonEmpty(req.header().apply(Guard.CODE_HEADER))).codeType(nonEmpty(req.header().apply(Guard.CODE_TYPE_HEADER)))
                .enroll(enroll).browserProof(nonEmpty(proof)).silentSignIn(silent);
    }

    private static RelayResponse guardResponse(Guard.Result result) {
        RelayResponse res = new RelayResponse(result.status(), result.body());
        if (result.retryAfter() != null) res.setHeader("Retry-After", String.valueOf(result.retryAfter()));
        return res.setHeader("Cache-Control", "no-store");
    }

    // ── Offline Sign ──────────────────────────────────────────────────────
    // The username used for onAuthenticated is the one Touchque returns for the code, never the body's.

    private RelayResponse offlineChallenge(RelayRequest<T> req) {
        if (!offlineEnabled) return offlineDisabled();
        Object[] lu = loginUser(req);
        if (lu[1] != null) return (RelayResponse) lu[1];
        String user = (String) lu[0];
        RelayResponse limited = allow(req, "offline-challenge", user, 1);
        if (limited != null) return limited;
        try {
            // requestId (the push this QR follows): a phone-side rejection kills the QR and the number carries over.
            String rid = bodyString(req.body(), "requestId");
            JsonNode c = tq.offline().challenge(new Offline.ChallengeOptions(user).type(o.actionType)
                    .details(o.getDetails == null ? null : o.getDetails.apply(req.nativeRequest()))
                    .clientIp(req.ip() != null && !req.ip().isEmpty() ? req.ip() : null).userAgent(req.userAgent()).requestId(rid.isEmpty() ? null : rid));
            ObjectNode out = Json.object();
            for (String k : new String[] {"challengeId", "qr", "qrDataUrl", "expiresAt", "expiresInSeconds"}) out.set(k, c.has(k) ? c.get(k) : null);
            out.put("totpAvailable", Json.bool(c, "totpAvailable"));
            if (!empty(Json.str(c, "challengeCode"))) out.put("challengeCode", Json.str(c, "challengeCode"));
            return new RelayResponse(200, out);
        } catch (RuntimeException e) {
            return relayError(e);
        }
    }

    private RelayResponse offlineVerify(RelayRequest<T> req) {
        if (!offlineEnabled) return offlineDisabled();
        RelayResponse limited = allow(req, "offline-verify", null, 1);
        if (limited != null) return limited;
        try {
            JsonNode r = tq.offline().verify(bodyString(req.body(), "challengeId"), bodyString(req.body(), "code"));
            String who = Json.str(r, "externalUsername");
            if (!Json.bool(r, "approved") || empty(who)) {
                ObjectNode no = Json.object().put("approved", false);
                Json.put(no, "reason", Json.str(r, "reason"));
                Json.put(no, "attemptsLeft", Json.integer(r, "attemptsLeft"));
                return new RelayResponse("invalid_code".equals(Json.str(r, "reason")) ? 401 : 400, no);
            }
            // With a first factor, the code must belong to the user who passed it.
            if (o.getLoginUser != null && !sameUser(o.getLoginUser.apply(req.nativeRequest()), who)) {
                return new RelayResponse(401, Json.object().put("approved", false).put("reason", "invalid_code"));
            }
            RelayResponse res = new RelayResponse(200);
            if (o.onAuthenticated != null) o.onAuthenticated.accept(req.nativeRequest(), res, new RelayAuthenticated(who, Json.str(r, "challengeId"), "offline"));
            ObjectNode body = Json.object().put("status", "success").put("approved", true);
            Json.put(body, "requestId", Json.str(r, "challengeId"));
            return res.body(body);
        } catch (Exception e) {
            return relayError(e);
        }
    }

    private RelayResponse offlineTotp(RelayRequest<T> req) {
        if (!offlineEnabled) return offlineDisabled();
        Object[] lu = loginUser(req);
        if (lu[1] != null) return (RelayResponse) lu[1];
        String user = (String) lu[0];
        RelayResponse limited = allow(req, "offline-totp", user, 1);
        if (limited != null) return limited;
        try {
            String requestId = bodyString(req.body(), "requestId");
            JsonNode r = tq.offline().verifyTotp(user, bodyString(req.body(), "code"), o.actionType,
                    req.ip() != null && !req.ip().isEmpty() ? req.ip() : null, requestId.isEmpty() ? null : requestId);
            String who = Json.str(r, "externalUsername");
            if (!Json.bool(r, "approved") || empty(who)) {
                ObjectNode no = Json.object().put("approved", false);
                Json.put(no, "reason", Json.str(r, "reason"));
                return new RelayResponse("invalid_code".equals(Json.str(r, "reason")) ? 401 : 400, no);
            }
            RelayResponse res = new RelayResponse(200);
            if (o.onAuthenticated != null) o.onAuthenticated.accept(req.nativeRequest(), res, new RelayAuthenticated(who, null, "offline-totp"));
            return res.body(Json.object().put("status", "success").put("approved", true));
        } catch (Exception e) {
            return relayError(e);
        }
    }

    // ── passkey: passwordless sign-in ─────────────────────────────────────

    private RelayResponse passkeyAuthenticateOptions(RelayRequest<T> req) {
        String email = bodyString(req.body(), "email").toLowerCase(Locale.ROOT);
        RelayResponse limited = allow(req, "passkey-options", email.isEmpty() ? null : email, 1);
        if (limited != null) return limited;
        try {
            return new RelayResponse(200, tq.webauthn().primaryOptions(email.isEmpty() ? null : email));
        } catch (RuntimeException e) {
            return relayError(e);
        }
    }

    private RelayResponse passkeyAuthenticateVerify(RelayRequest<T> req) {
        RelayResponse limited = allow(req, "passkey-verify", null, 1);
        if (limited != null) return limited;
        try {
            JsonNode r = tq.webauthn().primaryVerify(bodyString(req.body(), "attemptId"), bodyObject(req.body(), "response"));
            if (Json.bool(r, "success")) {
                RelayResponse res = new RelayResponse(200);
                String who = Json.str(r, "externalUsername");
                if (o.onAuthenticated != null) o.onAuthenticated.accept(req.nativeRequest(), res, new RelayAuthenticated(who != null ? who : "", Json.str(r, "requestId"), "passkey"));
                ObjectNode body = Json.object().put("status", "success");
                Json.put(body, "requestId", Json.str(r, "requestId"));
                return res.body(body);
            }
            if (Json.bool(r, "requiresStepUp")) return new RelayResponse(200, Json.object().put("requiresStepUp", true));
            return new RelayResponse(401, Json.object().put("error", "verification_failed"));
        } catch (Exception e) {
            return relayError(e);
        }
    }

    // ── passkey: approve a pending 2FA request (second factor) ────────────

    private RelayResponse passkeyLoginOptions(RelayRequest<T> req) {
        RelayResponse limited = allow(req, "passkey-approve", null, 1);
        if (limited != null) return limited;
        try {
            return new RelayResponse(200, tq.webauthn().authenticateOptions(bodyString(req.body(), "requestId")));
        } catch (RuntimeException e) {
            return relayError(e);
        }
    }

    private RelayResponse passkeyLoginVerify(RelayRequest<T> req) {
        RelayResponse limited = allow(req, "passkey-approve", null, 1);
        if (limited != null) return limited;
        try {
            JsonNode r = tq.webauthn().authenticateVerify(bodyString(req.body(), "requestId"), bodyObject(req.body(), "response"));
            String who = Json.str(r, "externalUsername");
            boolean success = Json.bool(r, "success");
            // Open the session only for the user Touchque says was approved; a name the browser sent is never trusted.
            if (success && o.getLoginUser != null && who != null && !sameUser(o.getLoginUser.apply(req.nativeRequest()), who)) {
                return new RelayResponse(401, Json.object().put("error", "verification_failed"));
            }
            RelayResponse res = new RelayResponse(200);
            if (success && o.onAuthenticated != null && !empty(who)) {
                String requestId = !empty(Json.str(r, "requestId")) ? Json.str(r, "requestId") : bodyString(req.body(), "requestId");
                o.onAuthenticated.accept(req.nativeRequest(), res, new RelayAuthenticated(who, requestId, "passkey"));
            }
            return res.body(r);
        } catch (Exception e) {
            return relayError(e);
        }
    }

    // ── passkey: enrollment / management (signed in) ──────────────────────

    /**
     * A user with a linked phone approves adding a passkey there first: a passkey approves requests on
     * its own, so a stolen session must not be able to add one. Same two-phase contract as /login:
     * 202 with the step until approved, then the options.
     */
    private RelayResponse passkeyRegisterOptions(RelayRequest<T> req) {
        String userId = userId(req);
        if (userId == null) return unauthorized();
        Guard.Input input = guardInput(req, userId, PASSKEY_ENROLL_ACTION, null, false, null);
        try {
            if (req.header().apply(Guard.TOKEN_HEADER) == null || req.header().apply(Guard.TOKEN_HEADER).isEmpty()) {
                try {
                    return new RelayResponse(200, tq.webauthn().registerOptions(userId, true, null));
                } catch (TouchqueApiException e) {
                    if (!(e.status() == 403 && "enrollment_approval_required".equals(e.code()))) throw e;
                }
            }
            RelayResponse limited = Guard.isStatusPoll(tq, input) ? allow(req, "login-poll", null, POLLS_PER_ATTEMPT) : allow(req, "passkey-enroll", userId, 1);
            if (limited != null) return limited;
            Guard.Result result = Guard.run(tq, input);
            if (result.approved() == null) return guardResponse(result);
            return new RelayResponse(200, tq.webauthn().registerOptions(userId, true, result.approved().requestId()));
        } catch (RuntimeException e) {
            return relayError(e);
        }
    }

    private RelayResponse passkeyRegisterVerify(RelayRequest<T> req) {
        String userId = userId(req);
        if (userId == null) return unauthorized();
        try {
            JsonNode label = req.body().get("label");
            return new RelayResponse(200, tq.webauthn().registerVerify(userId, bodyObject(req.body(), "response"), label != null && label.isTextual() ? label.textValue() : null));
        } catch (RuntimeException e) {
            return relayError(e);
        }
    }

    private RelayResponse passkeyCredentials(RelayRequest<T> req) {
        String userId = userId(req);
        if (userId == null) return unauthorized();
        try {
            ObjectNode body = Json.object();
            body.set("credentials", tq.webauthn().listCredentials(userId));
            return new RelayResponse(200, body);
        } catch (RuntimeException e) {
            return relayError(e);
        }
    }

    private RelayResponse deleteCredential(RelayRequest<T> req, String id) {
        String userId = userId(req);
        if (userId == null) return unauthorized();
        try {
            return new RelayResponse(200, Json.object().put("deleted", tq.webauthn().deleteCredential(id, userId)));
        } catch (RuntimeException e) {
            return relayError(e);
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private String userId(RelayRequest<T> req) {
        return nonEmpty(o.getUserId.apply(req.nativeRequest()));
    }

    /** Who a pre-auth route acts for: the first-factor user when configured, otherwise the typed username. {user, refusal}. */
    private Object[] loginUser(RelayRequest<T> req) {
        if (o.getLoginUser != null) {
            String u = o.getLoginUser.apply(req.nativeRequest());
            if (empty(u)) {
                return new Object[] {null, new RelayResponse(401, Json.object().put("error", "FIRST_FACTOR_REQUIRED").put("message", "Sign in with your password first."))};
            }
            return new Object[] {u.toLowerCase(Locale.ROOT), null};
        }
        String typed = bodyString(req.body(), "externalUsername").toLowerCase(Locale.ROOT);
        if (typed.isEmpty()) return new Object[] {null, new RelayResponse(400, Json.object().put("error", "externalUsername_required"))};
        return new Object[] {typed, null};
    }

    /** Null when allowed; otherwise the 429 to send (this IP or this user is over the limit for the route). */
    private RelayResponse allow(RelayRequest<T> req, String route, String user, int ipFactor) {
        if (limiter == null) return null;
        int ipWait = limiter.hit("ip|" + route + "|" + (req.ip() != null && !req.ip().isEmpty() ? req.ip() : "unknown"), limiter.perIp() * ipFactor);
        int userWait = empty(user) ? 0 : limiter.hit("user|" + route + "|" + user, limiter.perUser());
        int wait = Math.max(ipWait, userWait);
        if (wait == 0) return null;
        return new RelayResponse(429, Json.object().put("error", "RATE_LIMITED").put("message", "Too many attempts. Try again later.").put("retryAfter", wait))
                .setHeader("Retry-After", String.valueOf(wait));
    }

    private static RelayResponse unauthorized() {
        return new RelayResponse(401, Json.object().put("error", "UNAUTHORIZED_FOR_2FA")
                .put("message", "Could not find user ID in request. Put your own auth in front of this relay."));
    }

    private static RelayResponse offlineDisabled() {
        return new RelayResponse(403, Json.object().put("error", "OFFLINE_REQUIRES_FIRST_FACTOR")
                .put("message", "Offline sign-in is disabled: configure getLoginUser (or allowOfflineWithoutFirstFactor) on the Touchque relay."));
    }

    /** Same status mapping as the guard middleware, kept in sync with the Node SDK. */
    private RelayResponse authResultError(Exception e) {
        if (e instanceof TouchqueRejectedException) {
            return new RelayResponse(403, Json.object().put("error", "2FA_REJECTED").put("message", "User rejected the 2FA request on their device."));
        }
        if (e instanceof TouchquePasskeyRequiredException p) {
            return new RelayResponse(409, Json.object().put("error", "PASSKEY_REQUIRED").put("requestId", p.requestId()).put("message", "Approve this sign-in with your passkey."));
        }
        if (e instanceof TouchqueTimeoutException) {
            return new RelayResponse(408, Json.object().put("error", "2FA_TIMEOUT").put("message", "User did not respond to the 2FA request in time."));
        }
        if (e instanceof TouchqueApiException a && a.status() < 500) {
            String text = firstText(a.error(), Json.str(a.body(), "message"), a.getMessage());
            return new RelayResponse(a.status(), Json.object().put("error", text != null ? text : "request_failed"));
        }
        tq.http().log().error("[Touchque Relay Error] " + SdkLog.describe(e));
        return new RelayResponse(503, Json.object().put("error", "2FA_UNAVAILABLE").put("message", "The 2FA verification service is temporarily unavailable."));
    }

    /**
     * For plain relay routes: a client-range Touchque status is forwarded with its machine-readable
     * code only (never Touchque's message text); anything else is 502.
     */
    private RelayResponse relayError(Exception e) {
        if (e instanceof TouchqueApiException a && a.status() < 500) {
            String text = firstText(a.code(), a.error());
            return new RelayResponse(a.status(), Json.object().put("error", text != null ? text : "request_failed"));
        }
        tq.http().log().error("[Touchque Relay Error] " + SdkLog.describe(e));
        return new RelayResponse(502, Json.object().put("error", "relay_error"));
    }

    private static String firstText(String... candidates) {
        for (String c : candidates) {
            if (c != null && !c.isEmpty()) return c;
        }
        return null;
    }

    private static boolean sameUser(String expected, String actual) {
        return !empty(expected) && expected.toLowerCase(Locale.ROOT).equals(actual.toLowerCase(Locale.ROOT));
    }

    /** A body field as a string ("" when missing or not a scalar). */
    private static String bodyString(ObjectNode body, String field) {
        JsonNode v = body == null ? null : body.get(field);
        if (v == null || v.isNull() || v.isContainerNode() || v.isBoolean()) return "";
        return v.isTextual() ? v.textValue() : v.toString();
    }

    private static JsonNode bodyObject(ObjectNode body, String field) {
        JsonNode v = body == null ? null : body.get(field);
        return v != null && v.isObject() ? v.deepCopy() : Json.object();
    }

    private static String nonEmpty(String s) {
        return s == null || s.isEmpty() ? null : s;
    }

    private static boolean empty(String s) {
        return s == null || s.isEmpty();
    }
}
