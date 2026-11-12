# Touchque for Java

The official Java server SDK for [Touchque](https://touchque.com). It covers push approvals with number
matching, passkeys, silent sign-ins, offline codes, verified webhooks, Touchque Actions, AI agent
approvals, Touchque Login (hosted sign-in and the Management API) and the server side of the
Mobile SDK.

| Artifact | What it is |
| --- | --- |
| `com.touchque:touchque-java` | The client. Java 17+, `java.net.http`, Jackson, unchecked exceptions, silent unless you pass a logger. |
| `com.touchque:touchque-spring-boot-starter` | Spring Boot 3 auto-configuration: the client bean, `@RequireTouchque` on controller methods, the relay routes `@touchque/web` needs, verified webhooks, Touchque Login through Spring Security, MCP server protection. |

📘 Full docs: **[support.touchque.com](https://support.touchque.com)**

## Install

Maven:

```xml
<dependency>
  <groupId>com.touchque</groupId>
  <artifactId>touchque-spring-boot-starter</artifactId>   <!-- Spring Boot (brings touchque-java) -->
  <version>5.2.0</version>
</dependency>
```

Gradle:

```kotlin
implementation("com.touchque:touchque-spring-boot-starter:5.2.0")   // Spring Boot
implementation("com.touchque:touchque-java:5.2.0")                  // anything else
```

## Setup

Get an API key and secret from your [Touchque dashboard](https://dashboard.touchque.com):

```bash
export TQ_API_KEY=tq_auth_your_key
export TQ_API_SECRET=your_api_secret
```

The secret signs every request. Keep it on your server: never put it in a browser or an app.

```java
var tq = new TouchqueClient();                                                           // TQ_API_KEY / TQ_API_SECRET
var tq = new TouchqueClient(new TouchqueOptions().apiKey("tq_…").apiSecret("…"));         // or your own configuration
```

`TouchqueClient` is thread-safe: create one and reuse it. In Spring Boot it is a bean, configured
with `touchque.api-key`, `touchque.api-secret` and `touchque.base-url`; anything you leave out
comes from the environment.

## Quick start (Spring Boot)

Put one annotation on each protected controller method:

```java
@PostMapping("/transfer")
@RequireTouchque("SEND_MONEY")
Receipt transfer(@RequestBody Transfer t, Approval approval) {   // only reached once the user approved
    return payments.send(t);
}

@Bean
TouchqueGuardOptions sendMoney() {   // what the phone shows for this action
    return TouchqueGuardOptions.forAction("SEND_MONEY")
        .details(c -> List.of(LoginDetail.of("Amount", c.argument(Transfer.class).amount()),
                              LoginDetail.of("To", c.argument(Transfer.class).to())));
}
```

Until the user approves on their phone, the request gets `202 {"touchque": step, "token": "..."}`.
Your page shows the step in its own design. It then sends the same request again with the header
`X-Touchque-Token` (`@touchque/web` does this for you). Once approved, the method runs once.
By default, the approver is the signed-in user: their email, else sub, else name.
`TouchqueGuardOptions` can name someone else (`user`), a `referenceId`, a `context` for your
Touchque Actions, `silentSignIn(Guard.SilentSignIn.on())`, `enroll(false)` (no first-time QR: a
user with no phone gets 202 with reason `enrollment_off`) and `errorBody`. Refusals answer 403
(rejected, blocked), 408 (expired), 423 (frozen) or 429 (rate limited), with `Retry-After` on
the last two and `Cache-Control: no-store` on every answer. Every refusal also
carries `X-Touchque-State: <state>`, and `X-Touchque-Reason: <reason>` when the step has one. A
page on another origin must expose them (`Access-Control-Expose-Headers`).

### Refusals in your app's error shape (`errorBody`)

By default, 403, 408, 423 and 429 refusals answer `{"touchque": step, "token": "..."}`, and 401,
500 and 503 answer `{"touchque": step, "error": {"code": ..., "message": ...}}`. To keep your
app's own error shape, declare a `TouchqueErrorBody` bean (every guarded method) or set
`errorBody` on one action's `TouchqueGuardOptions`:

```java
@Bean
TouchqueErrorBody touchqueErrors() {
    return r -> Map.of("message", r.message(), "code", r.code());
}
// 403 {"message":"The approval was rejected.","code":"rejected","touchque":{"state":"rejected",...}}
```

- It is called for every answer with status 400 or more (401, 403, 408, 423, 429, 500, 503),
  never for a 202 step or on approval.
- `r.status()`; `r.code()`: the guard's `error.code`, else the step's `reason`, else its
  `state`; `r.message()`: the guard's message, else a sentence for the state ("The approval was
  rejected.", "The approval expired. Try again.", "Too many rejected approvals. Try again later.",
  "Too many attempts. Try again later.", "The approval was refused."); `r.touchque()`: the step.
- What it returns is written with your app's `ObjectMapper`. When that gives a JSON object (a
  Map, a record, a bean, an `ObjectNode`), it is sent with `touchque` set to the step (the SDK's
  key wins, so `@touchque/web` still sees the state). No `token` is added. Anything else (a
  String, a number, a List, null) is sent as it is.
- The status and headers stay the same: JSON, `Cache-Control: no-store`, `Retry-After`,
  `X-Touchque-State`, `X-Touchque-Reason`. The callback gets a copy of the step.
- If it throws (a checked exception too), or returns what the `ObjectMapper` cannot write (a
  cycle, more than 1,000 levels of nesting), the default body is sent and `[Touchque] errorBody failed: <message>` is logged.
- Declare one such bean, or mark one `@Primary`: with two, refusals keep the default body.

### Without an API key

The client bean is looked up on each guarded request (the starter's is built on the first one and
kept; a prototype or per-tenant bean of yours is used as it is), so the app starts without
`TQ_API_KEY` / `TQ_API_SECRET`. Until they are set, a `@RequireTouchque` method never runs. It
answers 401 `unauthenticated` without a signed-in user, otherwise 500 with `Cache-Control: no-store`:

```json
{"touchque":{"state":"blocked","reason":"misconfigured"},"error":{"code":"misconfigured","message":"Two-factor approval is not configured correctly."}}
```

It is a 500 and not a 503 because it is a setup mistake to fix, not an outage to retry.
`@touchque/web` shows "Approvals are not set up correctly on this site." With `touchque.debug=true`
the SDK logs it once: `[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.`
The relay routes and the webhook endpoint still need the keys when the app starts. A guard inside
your own handler answers the same with `Guard.withoutClient(input)` (see below).

## Action types

`"SEND_MONEY"` above is an action type: one kind of approval, with the title the phone shows and
whether it is critical. Define each one once, in the dashboard (**Developers → Action types**)
or from code:

```java
tq.actionTypes().define("SEND_MONEY", "Send money", true);   // type, name, critical
```

The guard refuses what is not ready. A name that is not defined is a setup error
(`TouchqueConfigException`, "Unknown action …"): the guard answers 500 with `reason: "misconfigured"`. A type
turned off in the dashboard answers 403 with `reason: "action_disabled"`, which stops that kind of
approval at once, without a deploy.

## The three primitives (any framework)

```java
Step step = tq.start("SEND_MONEY", new StartOptions("jane@acme.com").details(List.of(LoginDetail.of("Amount", "250 EUR"))));
// step.state(): waiting (show step.number()) | enroll (show step.enroll().qrCodeDataUrl()) | passkey_required | blocked | frozen | rate_limited
Step now = tq.check(step.requestId());
Approval approval = tq.complete(step.requestId(),
    new CompleteExpectations("jane@acme.com", "SEND_MONEY", List.of(LoginDetail.of("Amount", "250 EUR")), null));
// uses the approval once, and only for this user, action and amount
```

## Guard inside your handler

`Guard.run` is the whole two-phase contract of `@RequireTouchque` as one call, for any framework
(Spring, Jakarta servlets, Micronaut, Quarkus, Javalin). Use it when your own checks must come
first. `Guard.response` turns its answer into the status, headers and JSON body that
`@RequireTouchque` and the relay send (they use it too):

```java
@RestController
class Transfers {
    private static final System.Logger LOG = System.getLogger("transfers");
    // The starter's client bean, looked up per request: it is built on the first one, not at startup.
    private final ObjectProvider<TouchqueClient> touchque;
    // Your app's ObjectMapper: an errorBody's result is written with it, as @RequireTouchque does.
    private final ObjectMapper objectMapper;

    Transfers(ObjectProvider<TouchqueClient> touchque, ObjectMapper objectMapper) {
        this.touchque = touchque;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/transfer")
    ResponseEntity<?> transfer(@RequestBody Transfer t, HttpServletRequest request) {
        String user = TouchqueSpring.user(request);
        // 1. Your own checks first (ownership, balance): a request you refuse anyway never reaches the phone.
        if (!accounts.canSend(user, t.amount())) return ResponseEntity.status(409).body(Map.of("error", "insufficient_funds"));

        Guard.Input input = new Guard.Input(user, "SEND_MONEY")
            .details(List.of(LoginDetail.of("Amount", t.amount()), LoginDetail.of("To", t.to())))
            .headers(request::getHeader)
            .ip(TouchqueSpring.clientIp(request))
            .userAgent(request.getHeader("User-Agent"));
        Guard.Result r;
        try {
            r = Guard.run(touchque.getObject(), input);
        } catch (BeansException noKeys) {   // no TQ_API_KEY / TQ_API_SECRET yet: 500 misconfigured (401 without a user)
            r = Guard.withoutClient(input);
        }
        if (r.approved() == null) {
            // 2. A step (202) or a refusal: its status, headers (Cache-Control, Retry-After, X-Touchque-*) and JSON body,
            //    refusals in your error shape, exactly as @RequireTouchque sends them.
            Guard.Response res = Guard.response(r, refusal -> Map.of("message", refusal.message(), "code", refusal.code()), objectMapper, LOG);
            return ResponseEntity.status(res.status()).headers(h -> res.headers().forEach(h::set)).body(res.body());
        }
        // 3. Approved: run the action once. The approval is used up.
        return ResponseEntity.ok(payments.send(t));
    }
}
```

- The client: with the starter, take `ObjectProvider<TouchqueClient>` and call `getObject()` per
  request, falling back to `Guard.withoutClient(input)` while it cannot be built. That client
  reads `touchque.*` (application.yml), then the environment. A plain `TouchqueClient` field or
  constructor parameter builds it at startup, so the app does not start without keys, and
  `@Lazy TouchqueClient` fails, because `TouchqueClient` is final and cannot be proxied.
- Without the starter, pass `null`: `Guard.run(null, input)` uses `Guard.defaultClient()`, built
  from `TQ_API_KEY`, `TQ_API_SECRET` and `TQ_API_URL` on the first request and kept (a failed
  build is tried again on the next one). It never reads `touchque.*`. While it cannot be built,
  the answer is 401 `unauthenticated` without a user, else 500 `misconfigured`, and
  `Guard.isStatusPoll(null, input)` is false.
- That null-client path logs nothing: the SDK's logger belongs to a client, and it is silent by
  default. To fail fast, call `Guard.defaultClient()` at startup: it throws
  `TouchqueConfigException`, naming the problem. To give the path a logger, set a client built with
  one: `Guard.setDefaultClient(new TouchqueClient(new TouchqueOptions().logger(logger)))`.
  `Guard.setDefaultClient(null)` forgets it, and the next call builds one from the environment again.
- Run it after your own checks (ownership, balance), with the details the phone shows, built on
  your server.
- Not approved: send `Guard.response(r, errorBody, objectMapper, logger)` as it is. Its headers
  are `Cache-Control: no-store`, `Retry-After` on 423 and 429, and on a refusal `X-Touchque-State`
  and `X-Touchque-Reason`. `errorBody` (null: the guard's body) is your shape for refusals, as in
  [Refusals in your app's error shape](#refusals-in-your-apps-error-shape-errorbody), and a
  `TouchqueErrorBody` bean works as it is. Its result is written with your `ObjectMapper`, and a
  failure is logged to your `System.Logger` as `[Touchque] errorBody failed: <message>`, so the
  answer is the one `@RequireTouchque` sends. The short form `Guard.response(r, errorBody)` writes
  with the SDK's own `ObjectMapper` and logs nothing; without an errorBody both are the same.
- Approved (`r.approved()` is set): run the action once. A replay of the same token is refused.
- 202 `{"touchque": step, "token": "..."}`: the page shows the step and sends the same request
  again with `X-Touchque-Token: <token>`, every ~1.5 s (`touchqueFetch` from `@touchque/web` does
  this). The token is bound to the user, action, details and `referenceId`.
- Waiting polls (`waiting`, `passkey_required`) carry the request's `expiresAt` on every answer,
  not only the first, so a page can stop by time on the latest one. It is the live expiry from
  Touchque's status answer: a Vishing Shield escalation to a passkey extends it to 180 s.
- While the first-time QR is up, polls answer `{state: "enroll", expiresAt}` without `enroll`:
  keep showing the QR you have. About 15 s before it expires, a new QR comes with
  `enroll.qrCodeDataUrl`, together with new recovery codes; the old QR and the old codes stop
  working. Pages on @touchque/web need 2.1.0.
- `enroll(false)` never shows a first-time QR: a user with no phone gets 202
  `{"state": "enroll", "reason": "enrollment_off"}`. `@touchque/web` 2.2.0 stops polling there and
  says no phone is linked yet.
- A 202 state other than `waiting` or `enroll` (`passkey_required`, `offline`, an `enroll` with a
  reason) needs `@touchque/web`, or your own UI following this contract.
- `Guard.isStatusPoll(tq, input)` is true for a poll that only reads a state (a push on its way,
  or a first-time QR with more than 15 s left), so your own rate limit can let it through. If it
  does, charge what such a poll may still start in `beforeStart(() -> ...)`: the guard calls it
  once, right before a first-time QR poll starts a push (the phone got linked) or a new QR, and
  answers your result instead when you return one. The relay routes do this, so every start is
  counted.
- `Guard.Refusal.of(r)` gives a refusal's status, code and message for your own error body.

## Waiting in one call

```java
Login.VerifyResult result = tq.login().verify(new LoginRequestOptions("jane@acme.com")
    .type("LOGIN").clientIp(ip).userAgent(userAgent)
    // Number matching: show the number now; the phone asks for it.
    .onChallenge(c -> { if (c.challengeCode() != null) notify("Pick " + c.challengeCode() + " on your phone"); }));
```

`verify` throws `TouchqueRejectedException`, `TouchqueTimeoutException` or
`TouchquePasskeyRequiredException`. On the last one, `reason()` is `policy` (approve with a
passkey) or `step_up` (the user tapped Approve during a call, and the request now waits for a
passkey). `tq.protect(request, () -> transfer())` runs your code only after an approval.

## Relay routes for `@touchque/web`

Declare the options as a bean. The starter mounts the routes at `touchque.relay.path`
(default `/touchque`):

```java
@Bean
RelayOptions<HttpServletRequest> touchqueRelay() {
    return new RelayOptions<HttpServletRequest>(TouchqueSpring::user)
        // The user who already passed your password step. Binds /login and the offline routes to them.
        .getLoginUser(req -> (String) req.getSession().getAttribute("password_verified_user"))
        .onAuthenticated((req, response, info) -> signIn(req, info.externalUsername()))
        .silentSignIn(Guard.SilentSignIn.on());   // a known browser with nothing new skips the push
}
```

Routes: `POST /login`, `/enroll/start`, `GET /enroll/status`, `/offline/challenge|verify|totp`,
`/passkey/authenticate/options|verify`, `/passkey/login/options|verify`,
`/passkey/register/options|verify`, `GET /passkey/credentials`, `DELETE /passkey/credentials/{id}`.
Pre-auth routes are rate limited: 20 per IP and 5 per username a minute. To share the limits
across instances, pass `rateLimit(…)` with a Redis store. The offline routes stay off until
`getLoginUser` is set, and so does the first-time QR on `/login`: without `getLoginUser`, a user
with no phone gets 202 `{"state": "enroll", "reason": "enrollment_off"}`. Adding a passkey for a
user with a linked phone waits for the phone first.
The relay runs after Spring Security, so your callbacks see the signed-in user. Its POSTs are
JSON, so exempt it from CSRF: `http.csrf(c -> c.ignoringRequestMatchers("/touchque/**"))`.
Outside Spring, call `new RelayHandler<>(tq, options).handle(new RelayRequest<>(…))` from your
own route.

## Webhooks

```java
@Bean
TouchqueWebhookListener webhooks() {
    return (event, request) -> {
        if (Webhook.EVENT_APPROVAL_REVOKED.equals(event.path("event").asText())) sessions.end(event.path("requestId").asText());
    };
}
```

The endpoint is `POST touchque.webhook.path` (default `/webhooks/touchque`). Each delivery is
checked first:

- the signature: your API secret over the canonical JSON;
- the signed timestamp: 5 minutes by default;
- the `jti`: a replay is answered 200 and your listener is not called again.

When your listener throws, the answer is 500 and the `jti` is released, so Touchque's retry of
that delivery runs your listener again instead of being answered as a duplicate.

The endpoint runs before Spring Security, because the signature is its authentication. The
starter registers an in-process replay cache. With several instances, declare your own
`Webhook.ReplayCache` bean, for example with Redis `SET NX EX` in `checkAndSet` and `DEL` in
`release`. Anywhere else, call `tq.webhook().verify(rawBody, signatureHeader, 300, cache)`, and
`cache.release(jti)` when your handler fails.

## Silent sign-ins

```java
Risk.CheckResult risk = tq.risk().check(new Risk.CheckOptions(user).browserProof(request.getHeader("X-Touchque-Browser")).clientIp(ip));
if (!risk.prompt()) signIn(user);   // a known browser, nothing new: no push
```

Silent sign-ins fail closed: only an answer of exactly `prompt: false` skips the phone.
`tq.risk().browsers(user)` lists a user's known browsers. `forgetBrowsers(user, null)` forgets
them, for example after a password reset.

## Passkeys, offline codes, recovery, help desk

- `tq.webauthn()`: options and verify for registration, second-factor and passwordless sign-in; list and delete passkeys.
- `tq.offline()`: QR challenges and typed codes while the phone is offline. While Touchque itself
  is unreachable, `totpVerifiers` and `Offline.matchTotpVerifier` check time-based codes.
- `tq.recovery()` (Never Locked Out): vouchers, `start` (show `bindUri` as a QR), `status`, `veto`.
- `tq.assist()` (help desk): `open`, `verify` (a 2-digit code the agent reads to the person), `spend`, `unfreeze`, `end`.
- `ApprovalProof.verify(proof, options)`: checks the phone's own signature over what it showed ("what you see is what you sign").

## Touchque Actions

```java
tq.actions().deploy("night-alert", new Actions.DeployOptions().trigger("approval.decided")
    .template(Actions.TemplateRef.of("alert", Map.of("channel", "slack", "when", Map.of("countries", List.of("TR"))))));
JsonNode replay = tq.actions().dryRun(new Actions.Draft().trigger("login.request").code(code).limit(500));
```

The resource also has `test`, `rollback`, `logs`, `metrics`, `templates` and `secrets()`.
Action code is JavaScript that Touchque runs in a sandbox, whatever language your server uses.
Action types: `tq.actionTypes().define("SEND_MONEY", "Send money", true)`.

## AI agents

Your server registers agents (public key only) and checks their approvals. Each agent signs in
with its own key:

```java
AgentKeys.Pair keys = AgentKeys.generate();             // where the agent runs; ES256 or "EdDSA"
tq.agents().create(new Agents.CreateOptions("Invoice bot", List.of("PAY_INVOICE")).publicKey(keys.publicJwk()));

// The agent (TQ_AGENT_ID, TQ_AGENT_KEY): private_key_jwt + DPoP, never your API key.
var bot = new TouchqueAgent();
var approved = bot.requireApproval("ayse@acme.com", "PAY_INVOICE", List.of(payment), null,
    s -> say("Type " + s.challengeCode() + " on your phone"), null);

// Your server, right before it pays:
JsonNode used = tq.agents().redeemApproval(approved.approvalToken(), new ApprovalToken.Expectation("ayse@acme.com", null, payment));
```

The SDK also covers:

- mandates (`requestMandate`);
- the token vault (`tq.agents().vault()`, `bot.getConnectionToken`);
- policies, blocks and the kill switch;
- offline token checks (`verifyApprovalToken`).

`TouchqueOrgAgent` is an organization's agent on Touchque SSO. It gets DPoP tokens for one app
and supports token exchange, CIBA, the token vault and shared accounts. It can use GitHub Actions
or Kubernetes tokens instead of a stored key.

`McpAuth` protects an MCP server whose authorization server is Touchque SSO. In Spring Boot, set
`touchque.mcp.issuer`, `touchque.mcp.resource` and `touchque.mcp.tools.<tool>=<scope>`. The
starter then serves the RFC 9728 metadata and checks every request to the resource's path. Those
requests carry a Touchque token and DPoP proof, not a session: answers are 401/403 with
`WWW-Authenticate`. In your handler, `mcpAuth.requireTool(TouchqueSpring.mcpClaims(request), tool)`
refuses a missing scope with 403. If Spring Security is on, permit the MCP path to pass through.
Behind a proxy, set `server.forward-headers-strategy`, because a DPoP proof names the URL the
client called.

### Cross App Access (ID-JAG) and A2A agent cards

Cross App Access (ID-JAG) is an open IETF draft. An organization's identity provider (Touchque
SSO) can let one of its apps reach another service for a member, with no consent screen. The app
trades the member's ID token for an ID-JAG, then trades the ID-JAG for an access token at the
other service. If you run an authorization server, the verifier checks an ID-JAG (issuer, single
audience, your client, expiry, `typ`) and uses it once.

Before your agent trusts another agent's A2A card, check its signatures (A2A 1.0 §8.4: a JWS over
the RFC 8785 canonical card). Keys named by `jku` are only fetched from the card's own host or
from hosts you trust.

```java
var jag = CrossAppAccess.requestIdJag(new CrossAppAccess.RequestOptions(clientId, secret, idToken, "https://auth.files.example")
    .issuer("https://sso.touchque.com"));
JsonNode tokens = CrossAppAccess.redeemIdJag(new CrossAppAccess.RedeemOptions("https://auth.files.example/token", "acme", jag.assertion())
    .clientSecret(filesSecret));

// Your own authorization server (jwt-bearer grant):
var verifier = new IdJagVerifier(new IdJagVerifier.Options("https://sso.touchque.com", "https://auth.files.example"));
IdJagVerifier.Claims claims = verifier.verify(form.get("assertion"), authenticatedClientId);

AgentCard.verify(cardJson, new AgentCard.VerifyOptions().cardUrl("https://agent.example/.well-known/agent-card.json"));
```

## Touchque Login (hosted sign-in)

Spring Boot, with Spring Security's OAuth2 client on the classpath:

```properties
touchque.login.domain=acme.login.touchque.com
touchque.login.client-id=…
touchque.login.client-secret=…
touchque.login.scope=openid,profile,email,offline_access
```

With no security chain of your own, every page now signs in with Touchque Login. It uses PKCE,
also for confidential apps. The sign-in starts at `/oauth2/authorization/touchque`, and sign-out
goes through Touchque (`/logout`). In your own `SecurityFilterChain`, call
`touchqueLogin.configure(http)`.

Your API checks Touchque Login access tokens with Spring Security's resource server. Set
`touchque.login.domain` and `touchque.login.audience=https://api.acme.com` to get a `JwtDecoder`.
It checks the tenant's keys (RS256), `typ` at+jwt, the issuer, expiry and that `aud` names your
API. Scopes become `SCOPE_` authorities.

Outside Spring, use `HostedLogin`, the OpenID Connect client. It does PKCE, ID token checks
(nonce, at_hash), refresh, token exchange, CIBA, the token vault, client credentials and logout.
`LoginSession` seals the sign-in state in encrypted cookies, in the same format as the Node and
Ruby SDKs:

```java
var login = new HostedLogin(new HostedLogin.Options("acme.login.touchque.com", clientId).clientSecret(secret).redirectUri("https://app/callback"));
var req = login.authorizationUrl(null);   // keep state, nonce, codeVerifier; redirect to req.url()
var tokens = login.handleCallback(callbackUrl, new HostedLogin.CallbackChecks(req.state(), req.nonce(), req.codeVerifier()));
```

The domain is reached over https. A plaintext `http://` domain is refused except on this machine
(localhost, 127.0.0.1, ::1, `*.localhost`), for `HostedLogin`, `MyAccount` and `touchque.login.domain`.

`login.myAccount(accessToken)` is the customer's own account API: profile, sign-in methods,
sessions, apps, data export and deletion. The Management API is `tq.identity()`: users, roles,
organizations, apps, connections, imports and exports, attack protection, and email and SMS
providers.

## Shared Signals (security events from Touchque SSO)

When something happens to an organization member's account after sign-in, Touchque SSO sends a
Security Event Token (SET, OpenID Shared Signals Framework 1.0) to the receivers the
organization's admin adds (Organization > Continuous access): CAEP `session-revoked`,
`credential-change`, `device-compliance-change`, RISC `account-disabled`, `credential-compromise`.
End the person's sessions or ask them to sign in again. `txn()` is the case code of Touchque's
decision.

Push delivery (RFC 8935): the SET is the request body.

```java
var verifier = new SecurityEventVerifier(new SecurityEventVerifier.Options("https://sso.touchque.com", "https://app.example.com"));

@PostMapping(value = "/ssf", consumes = "application/secevent+jwt")
ResponseEntity<?> ssf(@RequestBody String body) {
    try {
        SecurityEventVerifier.SecurityEvent event = verifier.verify(body);
        if (handled.add(event.jti()) && "session-revoked".equals(event.name())) sessions.endFor(event.subject().path("email").asText());
        return ResponseEntity.accepted().build();
    } catch (TouchqueSecurityEventException e) {
        // temporarily_unavailable: the keys could not be read; 503 and the transmitter tries again.
        int status = "temporarily_unavailable".equals(e.error()) ? 503 : 400;
        return ResponseEntity.status(status).body(Map.of("err", e.error(), "description", e.getMessage()));
    }
}
```

Poll delivery (RFC 8936), with the stream's poll endpoint and token: each poll acknowledges what
the last one returned.

```java
SecurityEventVerifier.PollResult page = SecurityEventVerifier.poll(
        new SecurityEventVerifier.PollOptions(pollUrl, streamToken).ack(handledLastTime).returnImmediately(true));
handledLastTime = new ArrayList<>();
for (Map.Entry<String, String> set : page.sets().entrySet()) {   // jti -> SET
    handle(verifier.verify(set.getValue()));
    handledLastTime.add(set.getKey());
}
// page.moreAvailable(): poll again right away. Report a SET you could not handle in setErrs(…), not in ack.
```

The verifier reads the transmitter's keys from its `/.well-known/ssf-configuration` (or
`jwksUri(…)`, or pinned `jwks(…)`) and checks the RS256 signature, `typ`, the issuer, your
audience and that the SET carries one event. A SET does not expire: it says what happened, so keep
the jtis you handled and skip a repeat.

## Mobile SDK (your own app approves)

```java
JsonNode e = tq.mobile().createEnrollment(userId, false, null);   // the app spends e.enrollmentToken
Mobile.Push push = Mobile.pushFromWebhook(webhookEvent);           // a MOBILE_PUSH webhook → APNs payload / FCM data
```

Or give Touchque your APNs key or FCM service account (`updateSettings`), and Touchque sends the
pushes for you.

## Pairing a browser by QR code

Your page shows a QR code and the person scans it with the Touchque app. The phone that scanned
is the one asked to approve, with number matching. Your page sends the thumbprint of its browser
key (`@touchque/web` `browserKey.thumbprint()`). The nonce in the QR never leaves your server:
Touchque keeps only its hash.

```java
QrPairings.Created p = tq.qrPairings().create(new QrPairings.CreateOptions(thumb).clientIp(ip).userAgent(userAgent));
// show p.uri() (touchque://pair-browser?...) as a QR code; poll:
JsonNode now = tq.qrPairings().get(p.pairingId());   // waiting -> scanned -> confirmed
if ("confirmed".equals(now.path("state").asText()))
    tq.login().request(new LoginRequestOptions(now.path("externalUsername").asText()).qrPairing(p.pairingId()));
// or: tq.qrPairings().refuse(p.pairingId(), "device_not_approved", "Ask IT to approve this computer.", null, null);
```

`get` returns these states:

- `scanned` or `confirmed`: a phone holding one of your users' accounts read the QR. The answer
  includes `proximity` (same network, same country).
- `reported`: the person said someone told them to scan it. Their 2FA freezes.

`refuse` tells the phone why your own checks said no.

## A code typed back on the phone

When a sign-in needs a code another service sent the person (a text message, WhatsApp, e-mail), ask them to type it on the phone instead. The phone encrypts it to a one-time key you made for this request: Touchque only ever holds the ciphertext. Such a request lives 5 minutes.

```java
CodeReply.Key key = CodeReply.newKey();   // keep key.privateKey() for this request
Login.RequestResult sent = tq.login().request(new LoginRequestOptions(user).reply(key.publicKey(), "sms", "+**********26"));
Login.Status status = tq.login().status(sent.requestId());   // once CONFIRMED
String code = status.reply() == null ? null : CodeReply.open(key.privateKey(), sent.requestId(), status.reply().get("ct").asText());
```

## Safe Guard (Safe transactions approved on the phone)

TouchqueSafeGuard is a transaction guard for a Safe: a transaction runs only with approvals signed by the P-256 keys on its approvers' phones. You send the raw transaction; the phone decodes it itself, shows its own rows and signs what it computed with a key only its biometrics unlock. Delegatecalls, changes to the Safe and proxy upgrades are governance: scheduled, time-locked and vetoable. A phone without that key yet gets `409 crypto_key_missing`.

```java
SafeTx tx = new SafeTx("1", safe, guard).to(to).value("0").data(data).operation(0).nonce("42")
        .config(2, 3, 172800, 259200).batchTarget(multiSendCallOnly)
        .approverIndex(0);   // this approver's index in the guard
JsonNode sent = tq.safeGuard().request(new SafeGuard.RequestOptions("treasurer@acme.com", "safe_payment", tx));   // an action type from your dashboard
JsonNode done = tq.safeGuard().waitForApproval(sent.path("requestId").asText(), null, null);   // 5 minutes at most
String approval = done.path("safeTx").path("approval").asText();

// Check it yourself: your own transaction, the approver's key from the guard on chain. Name what you
// are about to do: "approve" executes it (the default), "schedule" starts a governance change's waiting time.
String purpose = governance ? "schedule" : "approve";   // your own decision: a delegatecall, a change to the Safe, a proxy upgrade
SafeApproval.Verification check = SafeApproval.verify(tx, approval, approverKey, new SafeApproval.VerifyOptions().purpose(purpose).approverIndex(0));
if (!check.valid()) throw new IllegalStateException("approval refused: " + check.reason());
String payload = "approve".equals(purpose)
        ? SafeApproval.withApprovals(ownerSignatures, List.of(approval))                 // execTransaction(…, signatures)
        : SafeApproval.scheduleCall(safe, check.governanceHash(), List.of(approval));   // a call to the guard; runs after govDelay
```

`SafeApproval.verify` makes the guard's check off chain, so a co-signer or your own server never has to trust Touchque: it computes the Safe transaction hash (EIP-712) and the governance hash from the raw fields, rebuilds the 149-byte message the phone signed and checks the P-256 signature. It refuses a high `s`, an approval that expired or is valid for more than a day, another approver index, and, when you pass `rows` or `displayDigest` from your own decoding, rows the phone did not show. Without `purpose` it accepts only an ordinary approval (`approve`): a governance approval carries no Safe nonce and only starts the guard's waiting time, so it passes only when you name `purpose("schedule")`. `reason()` is `approval_malformed`, `public_key_invalid`, `approver_index_mismatch`, `approval_expired`, `rows_differ`, `high_s` or `signature_invalid`. `SafeApproval.safeTxHash`, `governanceHash`, `message` and `displayDigest` are public too; `SafeTx.fromJson` reads the API's `safeTx` shape.

## Errors, case codes and retries

| Exception (all unchecked) | When |
| --- | --- |
| `TouchqueApiException` | Touchque answered with an error: `status()`, `code()` (`device_not_linked`, `already_used`…), `caseCode()`, `retryAfter()`, `body()` |
| `TouchqueNetworkException` | the request never reached Touchque (safe to retry) |
| `TouchqueRejectedException`, `TouchqueTimeoutException`, `TouchquePasskeyRequiredException` | `verify` outcomes |
| `TouchqueWebhookSignatureException`, `TouchqueWebhookReplayException` | webhooks |
| `TouchqueApprovalException`, `TouchqueApprovalMismatchException` | agent approvals |
| `TouchqueConfigException` | a missing key, an unknown action type, a wrong argument |

A feature your organization cannot use here throws a `TouchqueFeatureException` (still a `TouchqueApiException`, status 403) with `feature()` (`device_risk`, `ai_agents`…) and `featureReason()`: `TouchqueFeatureNotInPlanException`, `TouchqueFeatureReadOnlyException` or `TouchqueFeatureOffException` — not in its plan (an owner or admin adds it in the Touchque dashboard), being turned off (reads work for 14 days, changes are refused) or switched off on this Touchque deployment.

**"Why?" case codes.** Refusals and pushes carry a 6-character case code (`K7P-2QX`). Show it to
the user ("Tell your support team: K7P-2QX"). Your team opens the whole decision by that code in
the dashboard.

**Retries.** Every request is signed with a one-time nonce, so the SDK never replays a request.
Don't wrap the client in a retry layer. Retry `TouchqueNetworkException` at the call site, and on
429 or 423 wait `retryAfter()` seconds. The client never follows redirects and refuses plain
`http://` except for localhost. If you pass your own `HttpClient`, build it with
`HttpClient.Redirect.NEVER`.

**Logging.** The SDK writes nothing to any log on its own. To see its own problems (a misconfigured
guard or missing keys behind one, an `errorBody` or `onChallenge` that threw, a relay error or a
relay without `getLoginUser`, a silent sign-in check that failed), pass a `System.Logger`: `new TouchqueOptions().logger(System.getLogger("com.acme.touchque"))`,
or `debug(true)` for System.Logger `touchque`. In Spring Boot, set `touchque.debug=true` and the
level with `logging.level.touchque`. Lines carry an error's class, code and message, never a
request or a user.

## Development

```bash
mvn verify        # needs Node.js: the tests run against testing/fake-touchque-api.mjs and fixtures
```

## License

MIT
