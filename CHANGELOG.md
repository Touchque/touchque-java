# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [5.2.0] — 2026-11-13

### Added
- **`Guard.run(null, input)`: the default client.** A null client is `Guard.defaultClient()`, built from `TQ_API_KEY`, `TQ_API_SECRET` and `TQ_API_URL` on the first request and kept; a build that fails is not kept, so the next request tries again. It is thread-safe. While it cannot be built, the guard answers 401 `unauthenticated` without a user, else 500 `misconfigured`, and never throws; nothing is logged then, since the SDK's logger belongs to a client. `Guard.isStatusPoll(null, input)` uses the same client and is false while there is none. It reads the environment only: with the Spring Boot starter, use its bean (see the README).
  - `Guard.setDefaultClient(client)` replaces it process-wide, for example with a client built with a logger, which gives the null-client path its log lines; `null` forgets it, so the next call builds one from the environment again.
  - To fail fast at startup, call `Guard.defaultClient()`: it throws `TouchqueConfigException`, naming the problem.
- **`Guard.response(result, errorBody)` → `Guard.Response(status, headers, body)`: a guard result as its HTTP answer.** For a step or a refusal (an approval throws `IllegalArgumentException`): `Cache-Control: no-store`, `Retry-After` on 423 and 429, `X-Touchque-State` and `X-Touchque-Reason` on a refusal, and the JSON body. `errorBody` (`Guard.ErrorBody`) follows the 5.1 rules: refusals only (400 or more), an object gets `touchque` set to the step, anything else is sent as it is, a callback that throws (checked exceptions too) or a result that cannot be written sends the default body. `Guard.response(result, errorBody, objectMapper, logger)` gives the answer `@RequireTouchque` sends: it writes the result with your `ObjectMapper` and logs `[Touchque] errorBody failed: <message>` to your `System.Logger`. The two-argument form writes with the SDK's own `ObjectMapper` and logs nothing; without an errorBody the two are the same. No Spring needed.
  - The relay and the Spring Boot starter (`@RequireTouchque`, `TouchqueExceptionHandler`) build their answers with it, so a guard inside your handler answers exactly like them. The starter still writes an errorBody's result with the app's `ObjectMapper`.
  - `TouchqueErrorBody` is a `Guard.ErrorBody`, so the bean can be passed to `Guard.response(result, errorBody, objectMapper, logger)`. `TouchqueStepException.response()` holds the answer sent; its public constructors are unchanged.
- **Waiting polls carry `expiresAt`.** A `waiting` or `passkey_required` step with `expiresAt` puts it in its token as the claim `rx` (ms since the epoch), and every later poll answer for that request in those states carries `expiresAt`, also after a detour through the offline QR. Before, only the first answer had it, so a page reading the latest answer never stopped by time. A poll takes the live expiry from the status answer when it parses (a Vishing Shield escalation to a passkey extends the request to 180 s), else `rx`, and the re-issued token keeps the one used. With neither, no `expiresAt`, as before.
- `Login.Status.expiresAt()`: the request's live expiry from `GET /login/status` (null when the API did not say); the 15-argument constructor stays. The step of `tq.check(requestId)` carries it.

### Changed
- **`enroll(false)` says why.** A user with no phone on a guard that may not show a first-time QR (`Guard.Input.enroll(false)`, `TouchqueGuardOptions.enroll(false)`, `StartOptions.enroll(false)`, the relay's `/login` without `getLoginUser`) gets 202 `{"touchque":{"state":"enroll","reason":"enrollment_off"},…}` instead of a bare `enroll` step. `@touchque/web` 2.2.0 stops polling there and shows that no phone is linked yet.
- `Guard.Refusal.of(result)` takes the step from `result.step()` when the body has no `touchque` (a `beforeStart` hook's result).
- README, "Guard inside your handler": the client comes from `ObjectProvider<TouchqueClient>` and `getObject()` per request, with `Guard.withoutClient(input)` while it cannot be built (a plain injection builds it at startup, and `@Lazy` fails because `TouchqueClient` is final); `Guard.run(null, …)` for apps without the starter, which logs nothing (fail fast with `Guard.defaultClient()` at startup, or give it a logger with `Guard.setDefaultClient`); the answer from `Guard.response(r, errorBody, objectMapper, logger)` with the app's `ObjectMapper`, as `@RequireTouchque` writes it. Also: a new first-time QR comes about 15 s before the old one expires, with new recovery codes, and the old QR and codes stop working; waiting polls carry `expiresAt`; `enroll(false)` answers `enrollment_off`; a 202 state other than `waiting` or `enroll` needs `@touchque/web` or your own UI following the contract.

## [5.1.0] — 2026-11-12

### Added
- **Spring Boot: `errorBody` keeps your app's error shape.** A `TouchqueErrorBody` bean (every `@RequireTouchque` method) or `TouchqueGuardOptions.errorBody(…)` (one action) receives every refusal with status 400 or more (401, 403, 408, 423, 429, 500, 503) as a `Guard.Refusal`: `status`, `code` (`error.code`, else the step's `reason`, else its `state`), `message` (`error.message`, else a sentence for the state) and `touchque` (the step). It is never called for a 202 step or on approval.
  - What it returns is written with the app's `ObjectMapper`. When that gives a JSON object (a Map, a record, a bean, an `ObjectNode`), it is sent with `touchque` set to the step, so `@touchque/web` still sees the state. No `token` is added.
  - Anything else (a String, a number, a List, null) is sent as it is. The status and headers stay the same (`Cache-Control: no-store`, `Retry-After`, `X-Touchque-State`, `X-Touchque-Reason`). The callback gets a copy of the step.
  - A callback that throws (a checked exception too, from Kotlin or `@SneakyThrows`), or a result the `ObjectMapper` cannot write (a cycle, more than 1,000 levels of nesting: it is written with the app's mapper and read back with the SDK's limits), logs `[Touchque] errorBody failed: <message>`, and the default body is sent.
  - The bean is looked up only for a refusal, and only when it is the one bean of its type (or `@Primary`): two of them leave refusals with the default body and never touch a 202 step.
  - `TouchqueStepException.body()` holds the body that is sent.
- **Refusal headers.** Every guard answer with status 400 or more, from `@RequireTouchque` and from the relay routes, carries `X-Touchque-State: <state>`, and `X-Touchque-Reason: <reason>` when the step has one. `@touchque/web` 2.1.0 reads the step from them when a body has no `touchque` (an errorBody's string, say). A page on another origin must expose them (`Access-Control-Expose-Headers`). `Guard.Result.refusalHeaders()`, `Guard.STATE_HEADER` and `Guard.REASON_HEADER` give them to a guard of your own.
- `Guard.Input.beforeStart(…)`: see the first-time linking fix below.
- `Guard.Refusal.of(result)`, `Guard.withoutClient(input)` (401 without a user, else 500 `misconfigured`) and `Step.withExpiresAt(…)`, for guards of your own.
- README: "Guard inside your handler" (`Guard.run` after your own checks, how to answer, running the action once, the 202 and first-time QR polls), the `errorBody` option and what a missing key answers.

### Fixed
- **First-time linking: one QR per enrollment, not one per poll.** In 5.0.0 every poll with an `enroll` token started again (login request, 404 `device_not_linked`, generate-secret 409, reset). Each 1.5 s poll replaced the QR and the recovery codes on screen, so the QR being scanned stopped working. Now:
  - An `enroll` step with a QR carries `enroll.expiresAt`: the API's `expiresAt` when it is ISO 8601, else now + `ttlMs`, else none. Its token carries that expiry as the claim `ee`.
  - A poll with that token only reads the link state (`auth().getUser`). Not linked and the QR good for more than 15 s: 202 `{"touchque":{"state":"enroll","expiresAt":…},"token":…}` without `enroll`, and the page keeps its QR. Linked: the push starts. Expired or about to, or the user unknown (404): a new QR. Other errors answer 503 `unavailable`.
  - `Guard.isStatusPoll` is true for such a poll while the QR has more than 15 s left, so the relay's per-user limit no longer refuses enrollment polls.
  - Every start is charged. `Guard.Input.beforeStart(…)` is called once, right before such a poll starts anything (a silent check or a push once the phone is linked, a new QR once the old one expired, is about to, or is gone), and a result it returns is answered instead. The relay's `POST /login` charges that start on the user's `login` limit like a fresh attempt and answers its usual 429 when it is over. So polls that only keep the QR are free, and replaying a first-time token can neither start pushes nor renew the secret on the poll budget.
  - A 5.0 token (no `ee`) works as before. Pages on `@touchque/web` need 2.1.0.
- **Spring Boot: a missing API key no longer throws on a guarded request.** The client bean was already built on first use, so the app started, but a `@RequireTouchque` method then failed with the bean's creation error. Now the guard looks the client bean up on each guarded request, inside its error handling (the starter's is a lazy singleton, built once; a prototype or per-tenant bean of yours is used as it is, never frozen to the first one). While it cannot be built (no `TQ_API_KEY` / `TQ_API_SECRET`), the method never runs: it answers 500 `misconfigured` (401 `unauthenticated` without a signed-in user) with `Cache-Control: no-store`. With `touchque.debug` the SDK logs once: `[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.` The relay routes and the webhook endpoint still need the keys at startup.

## [5.0.0] — 2026-11-11

### Breaking
- **Every name is spelled Touchque instead of TouchQue.** The client and its options: `TouchQueClient` → `TouchqueClient`, `TouchQueOptions` → `TouchqueOptions`; the agents: `TouchQueAgent` → `TouchqueAgent`, `TouchQueOrgAgent` → `TouchqueOrgAgent`; every error class `TouchQue…Exception` → `Touchque…Exception` (`TouchQueException` → `TouchqueException`, `TouchQueApiException` → `TouchqueApiException`, `TouchQueNetworkException` → `TouchqueNetworkException`, `TouchQueConfigException` → `TouchqueConfigException`, and the verify, webhook, approval, feature, agent and security-event errors alike); `MyAccount.unlinkTouchQueApp()` → `unlinkTouchqueApp()`. The Spring Boot starter: `@RequireTouchQue` → `@RequireTouchque`, `TouchQueProperties` → `TouchqueProperties`, `TouchQueSpring` → `TouchqueSpring`, `TouchQueGuardOptions` → `TouchqueGuardOptions`, `TouchQueGuardContext` → `TouchqueGuardContext`, `TouchQueWebhookListener` → `TouchqueWebhookListener`, `TouchQueLogin` → `TouchqueLogin`, `TouchQueStepException` → `TouchqueStepException`, `TouchQueIssuerFilter` → `TouchqueIssuerFilter`, the auto-configuration `TouchQueAutoConfiguration` → `TouchqueAutoConfiguration` (listed in `AutoConfiguration.imports`) and its bean names (`touchQueClient` → `touchqueClient`, `touchQueLogin` → `touchqueLogin` and the others alike). The header constants on `Guard` are `X-Touchque-Token`, `X-Touchque-Offline`, `X-Touchque-Code`, `X-Touchque-Code-Type` and `X-Touchque-Browser` (were `X-TouchQue-…`); HTTP header names are case-insensitive, so servers are unaffected. The SDK's own exception messages and log lines say `Touchque` (`Touchque: …`, `[Touchque] …`). Code using the old names must be updated; nothing else changes: the Java packages (`com.touchque.*`), the Maven coordinates, the `touchque.*` properties and everything sent to Touchque stay as they are.

### Fixed
- The published POMs of `touchque-java` and `touchque-spring-boot-starter` carry the parent's `url` (https://touchque.com) and `scm` (https://github.com/Touchque/touchque-java) as they are, instead of with the module's artifactId appended (`https://touchque.com/touchque-java`, `https://github.com/Touchque/touchque-java/touchque-java`, `scm:git:https://github.com/Touchque/touchque-java.git/touchque-java`). The `scm` also has a `developerConnection` now.

### Changed
- The README has an "Action types" section: define a type once (dashboard → Developers → Action types, or from code); the guard answers 500 `misconfigured` for an undefined name and 403 `action_disabled` for one turned off.

## [4.2.0] — not published (these changes ship in 5.0.0)

### Security
- **The offline approval-token check refuses another workspace's token.** `GET /agents/jwks.json` is one key set for every Touchque workspace, and the check used to compare `aud` only when you passed an audience, so a token Touchque signed for someone else's workspace (their own phone, any person's name, any details) could pass your executor. Now:
  - `agents().verifyApprovalToken(token, audience, expect)` (a null or empty audience) uses this workspace's own audience by default: `agents().approvalAudience()` asks `GET /agents/approval-audience` once (`touchque:workspace:<id>`) and keeps it.
  - `ApprovalToken.verifyWith(token, jwks, audience, expect, now)` requires the audience. A missing or empty one throws TouchqueApprovalMismatchException (`audience is required`).
  - A token without `aud` is refused (`the approval token names no workspace`), as is one for another workspace (`the approval token is for another workspace`).
  - Breaking for callers of the low-level function who passed no audience: pass agents().approvalAudience()'s value.
  - `redeemApproval` was already safe: Touchque compares `aud` with your workspace there.

### Added
- **`deviceRisk().searchEvents(new DeviceRisk.SearchOptions()...)`: search your workspace's Device risk identifications**, newest first, one page at a time (`GET /device-risk/events`): `from`/`to` (7 days by default, at most 90, within your retention), `signal`, `stepUp`, `kind`, `origin`, `ip` (an address or a CIDR range; never returned), `account`, `visitorId`, `requestId`, `limit` (1 to 100) and the opaque `cursor` from the previous page's `nextCursor`. `DeviceRisk.SearchResult` record.
- `DeviceRisk.CheckResult.engine()` (String, null when absent): the engine's state for this check; `"unavailable"` when the risk engine could not be reached and the verdict is a safe default (`stepUp` true), so an outage can be told apart from risk. The 15-argument constructor stays.
- **`webauthn().primaryAvailability()`: is passkey sign-in on for your workspace?** `GET /webauthn/authenticate/primary/availability` answers `enabled` and `userVerification` (`required` or `preferred`, null when off). Ask before your sign-in page shows its passkey button and passkey autofill; when it is off, `primaryOptions` answers 403 `passwordless_login_disabled`.
- **Shared Signals: receive the security events an identity provider sends after sign-in.** Touchque SSO sends Security Event Tokens (OpenID Shared Signals Framework 1.0) for an organization's members to the receivers its admin adds (Organization > Continuous access): CAEP `session-revoked`, `credential-change`, `device-compliance-change`, RISC `account-disabled`, `credential-compromise`; `txn` carries the case code of Touchque's decision. `new SecurityEventVerifier(new SecurityEventVerifier.Options(issuer, audience).jwksUri(…).jwks(…).clockSkew(…)).verify(token)` returns a `SecurityEvent` record (`jti`, `issuer`, `audience`, `issuedAt`, `txn`, `subject`, `type`, `name`, `claims`) or throws `TouchqueSecurityEventException` with the RFC 8935 code to answer in `error()` (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`); `SecurityEventVerifier.poll(new PollOptions(url, token).ack(…).maxEvents(…))` for poll delivery (RFC 8936); `SecurityEventVerifier.TYPES`. The keys come from the issuer's `/.well-known/ssf-configuration`; a SET does not expire, so keep the jtis you handled. Tested against the shared vectors (`fixtures/security-event-vectors.json`).
- **Safe Guard: Safe transactions approved on the approver's phone, for TouchqueSafeGuard.** `tq.safeGuard().request(new SafeGuard.RequestOptions(externalUsername, type, safeTx))` sends the raw transaction (`SafeTx`, fluent; the phone decodes it itself and signs with a key only its biometrics unlock), `status(requestId)` and `waitForApproval(requestId, timeout, pollInterval)` hand back the 105-byte approval. `SafeApproval.verify(tx, approval, approverKey, new SafeApproval.VerifyOptions().purpose(…).approverIndex(…).rows(…) | displayDigest(…).now(…))` checks it the way the guard does, without trusting Touchque: the Safe transaction hash (EIP-712, Keccak-256 here) and the governance hash computed here, the 149-byte message, low `s`, the one-day expiry window, the P-256 signature. `SafeApproval.withApprovals(ownerSignatures, approvals)` for `execTransaction`, `SafeApproval.scheduleCall(safe, governanceHash, approvals)` for a governance change; `safeTxHash`, `governanceHash`, `message`, `displayDigest`. Tested against the shared vectors (`fixtures/safe-guard-vectors.json`).
- **Opt-in logging, silent by default.** `new TouchqueOptions().logger(System.Logger)` receives the SDK's own problems: a misconfigured guard (500 `misconfigured`), an `onChallenge` that threw, a relay error (502 `relay_error`, 503 `2FA_UNAVAILABLE`) or a relay without `getLoginUser`, a silent sign-in check that failed (the guard then asks the phone), and an unexpected error behind a guard's 503. `debug(true)` with no logger writes them to System.Logger `touchque`; neither set, nothing is logged. No new dependency. Lines carry an error's class, code and message, never the error object, a request or a user, and a logger that throws never breaks a request. Spring Boot: `touchque.debug=true` (the `touchque` logger reaches Spring Boot's logging through its java.util.logging bridge).
- **Webhook events of Never Locked Out and the help desk** (`Webhook.EVENT_RECOVERY_*`, `Webhook.EVENT_ASSIST_*`), the names the API sends: `RECOVERY_STARTED`, `RECOVERY_DEVICE_BOUND`, `RECOVERY_COOLING`, `RECOVERY_COMPLETED`, `RECOVERY_VETOED`, `RECOVERY_EXPIRED`, `RECOVERY_FAILED`; `ASSIST_OPENED`, `ASSIST_ENDED`, `ASSIST_CHECK_PASSED`, `ASSIST_CHECK_FAILED`, `ASSIST_UNFROZEN`, `ASSIST_CLAIM_CONFIRMED`, `ASSIST_CLAIM_UNVERIFIED` (someone pretended to be IT).
- **Shared Signals: discovery and polling tested, and a README section.** The keys found through the issuer's `/.well-known/ssf-configuration` and `SecurityEventVerifier.poll` are tested against a local transmitter (the Node SDK's cases, plus metadata for another issuer and a refused poll); the README's "Shared Signals (security events from Touchque SSO)" shows verifying a pushed SET and polling.

### Fixed
- **Spring webhook endpoint: a delivery your listener failed on is handled when Touchque retries it.** When the `TouchqueWebhookListener` throws, the endpoint still answers 500 and now releases the delivery's `jti` (`Webhook.ReplayCache.release`, a new default method that `MemoryReplayCache` implements), so the retry runs the listener again instead of being answered 200 as a duplicate and lost. A `ReplayCache` of your own should implement `release` (Redis `DEL`).
- Usernames, emails, HTTP methods, content types, offline codes and IBANs are case-folded with `Locale.ROOT`. In a Turkish or Azerbaijani default locale, `Ilker@acme.com` became `ılker@acme.com`, and the relay pushed to, or offered first-time linking for, a user that does not exist.
- `complete()` and the guard treat an empty `referenceId` like none, as the API stores it: an approval started with `referenceId("")` was consumed and then refused as a mismatch. A mismatch after the approval in `Guard.run` (and so in `@RequireTouchque` and the relay) is now a 503 `unavailable` answer, as in the other SDKs, instead of an exception.
- Transaction details are trimmed the way the API trims them (JavaScript's `trim`): a label or value with a leading or trailing NBSP, U+FEFF, U+2028 or ideographic space gave another digest, so `complete()` refused a genuine approval and `ApprovalProof.verify` returned false.

### Security
- **Hosted login checks `iss` everywhere (RFC 9207).** `HostedLogin.handleCallback` now also refuses an empty `iss=` (`issuer_mismatch`), and the Spring Boot starter's `TouchqueLogin.configure(http)` adds a filter before Spring Security's callback, which reads only code, state and the error fields: a foreign or empty `iss` gets 400 `issuer_mismatch` before the code is exchanged and drops that pending sign-in. A callback without `iss` (a server that does not send it yet) is still accepted.
- **`SafeApproval.verify` without `purpose` accepts only an ordinary approval (`approve`).** A governance approval (`schedule`) passes only when you name `purpose("schedule")`. Before, a schedule approval, which carries no Safe nonce and only starts the guard's waiting time, also came back valid, so a co-signer that executes on `valid()` could execute on it.
- `HostedLogin`, `MyAccount` and the starter's Touchque Login (`touchque.login.domain`) refuse a plaintext `http://` domain except on this machine (localhost, 127.0.0.1, ::1, `*.localhost`), like the API `baseUrl`: codes, PKCE verifiers, the client secret and tokens would otherwise travel in the clear. `HostedLogin.issuerOf` is public.

## [4.1.0] — not published (these changes ship in 5.0.0)

### Added
- **Device risk events like a device-intelligence event, without raw traits:** `deviceRisk.check` and `getEvent` answers carry `network()`, `velocity()` and `bot()`: the address as the risk engine saw it (country, region, city, never coordinates; the operator; `type` isp, hosting or tor; `timezoneMismatch` when the browser's clock does not fit the address), the visitor's counts (accounts, sign-ups, countries, stored-id resets, identifications in the last hour and day) and one answer to "a bot?" (`detected`, `suspected` or `not_detected`, with reasons). The field the script tag fills may now carry its pointer summary after the requestId: pass it as it came.

### Changed
- `TouchqueApprovalMismatchException` does not name the other person in its message (the SDK writes nothing to any log).

### Added
- **A code typed back on the phone:** `LoginRequestOptions.reply(key, channel, target)`; `CodeReply.newKey()` and `CodeReply.open(privateKey, requestId, ct)` open `status(id).reply().get("ct")`.
- **Feature errors:** a feature your organization cannot use here (403 `feature_not_in_plan`, `feature_read_only`, `feature_off`) throws `TouchqueFeatureNotInPlanException`, `TouchqueFeatureReadOnlyException` or `TouchqueFeatureOffException`, all `TouchqueFeatureException` (`feature()`, `featureReason()`) and still `TouchqueApiException`.

First release of the Java SDK and the Spring Boot starter, at the same surface as the Node,
Python, PHP, Go, .NET and Ruby SDKs 4.1.0.

### Added
- **Webhook events `DEVICE_RISK_SIGNAL` and `DEVICE_RISK_ALERT`** (`Webhook.EVENT_DEVICE_RISK_*`): a Device risk signal that asks for more (identifiers, signals and the engine's verdict, never a trait), and an alert rule of the workspace that went off. Signed like every event.
- **Device risk in one line: `tq.deviceRisk().check(request.getParameter("touchque_request_id"))`** (or `check(CheckOptions.ofRequest(…).event("sign_up").externalUsername(email))`) with the script tag (`device.js`, `@touchque/web` 1.6.0), which fills that field. Pass it as it came: null, empty, made up or expired is still a verdict (`report` missing, unknown, expired, invalid; the signal `device_identification_missing`, a number-matched step-up at most), never an exception. `DeviceRisk.REPORTS`.
- **Device risk: `tq.deviceRisk().check(DeviceRisk.CheckOptions.ofRequest(requestId).event("sign_up")...)` and `tq.deviceRisk().getEvent(requestId)`** (a paid add-on; 409 `device_risk_off` until the workspace turns it on), and `deviceRiskRequestId(...)` (or `deviceRisk(...)`) on `LoginRequestOptions` and `Risk.CheckOptions`. The page's requestId comes from `@touchque/web` `deviceRisk.identify`. Every signal only ever asks for more (`stepUp`, never a refusal); signals start in shadow. `DeviceRisk.parseCheck`, `DeviceRisk.EVENTS`.
- **`com.touchque:touchque-java`** (Java 17+, `java.net.http`, Jackson, unchecked exceptions, no logging):
  - `TouchqueClient` with these resources:
    - `auth()` and `login()` (request, status, `verify` with `onChallenge`, `consume`, `reportFraud`, recovery codes);
    - `webauthn()`;
    - `offline()` (QR and typed codes, outage verifiers);
    - `risk()` (silent sign-ins);
    - `actionTypes()` (Second Thought questions) and `actions()` (Touchque Actions and their secrets);
    - `recovery()` (Never Locked Out) and `assist()` (help desk);
    - `agents()` (the token vault, mandates, blocks, the kill switch, the workspace policy, agent events, approval tokens);
    - `identity()` (the Touchque Login Management API, including `clients().rotateSecret`, `users().endSession` and `exports().file`);
    - `mobile()` (the Mobile SDK's server side, `Mobile.pushFromWebhook`);
    - `qrPairings()`;
    - `webhook()` (signature, timestamp window, replay cache).
  - `start` / `check` / `complete`, `protect` and `Guard.run`: the two-phase step-up contract
    shared by every Touchque server SDK. It covers offline codes, silent sign-ins, Vishing Shield
    (provisional approvals, passkey step-up), Mirror Alarm canaries and "Why?" case codes.
  - `RelayHandler<T>`: the routes `@touchque/web` calls, framework-neutral, with rate limits
    (`RateLimit.Store`).
- **Pairing a browser by QR code: `tq.qrPairings()`.**
  - `create(new QrPairings.CreateOptions(keyThumbprint).clientIp(…).userAgent(…).browser(…).os(…).ttlSeconds(…))`
    returns `uri` (`touchque://pair-browser?...`) to show as a QR code. The nonce stays with you;
    Touchque keeps only its hash.
  - `get` says who scanned the QR and how near the phone was (`proximity`).
  - `refuse` tells the phone why your own checks said no.
  - `LoginRequestOptions.qrPairing` asks the phone that scanned, once, with number matching.
- **AI agents:**
  - `AgentKeys` (ES256 and EdDSA, RFC 7638 thumbprints).
  - `TouchqueAgent`: the agent's own private_key_jwt + DPoP client, with `requestApproval`,
    `requireApproval`, `waitForApproval`, mandates and the token vault.
  - `TouchqueOrgAgent`: an organization's agent on Touchque SSO. DPoP tokens, token exchange,
    CIBA, the token vault, shared accounts, and GitHub Actions or file tokens instead of a key.
  - `McpAuth` for an MCP server whose authorization server is Touchque SSO.
  - `ApprovalToken` checks and `ApprovalProof.verify`.
- **Cross App Access (ID-JAG) and A2A agent cards:**
  - `CrossAppAccess.requestIdJag` / `redeemIdJag`.
  - `IdJagVerifier`: checks typ, issuer, single audience, client and expiry, and uses each ID-JAG
    once (`firstUse` for a shared store).
  - `AgentCard.verify` / `sign` / `canonicalJson` (RFC 8785).
- **Touchque Login:**
  - `HostedLogin`: an OpenID Connect client with PKCE, ID token checks (nonce, at_hash), refresh,
    token exchange, CIBA, the token vault, client credentials, logout and `verifyAccessToken`.
  - `MyAccount`: the customer's own account API, with step-up errors.
  - `LoginSession`: encrypted cookies, in the same format as the Node and Ruby SDKs.
- **`com.touchque:touchque-spring-boot-starter`** (Spring Boot 3):
  - the `TouchqueClient` bean from `touchque.*`, then the environment;
  - `@RequireTouchque("ACTION")` on controller methods or classes: a 202 step until the phone
    approves, then the method runs once, with an `Approval` parameter. Per-action
    `TouchqueGuardOptions` beans set details, the user, context and silent sign-ins.
  - the relay routes at `touchque.relay.path`, with a `RelayOptions<HttpServletRequest>` bean;
  - verified webhooks at `touchque.webhook.path`, with a `TouchqueWebhookListener` bean
    (401 on a bad signature, 200 `duplicate` on a replay);
  - Touchque Login through Spring Security OAuth2 login (`touchque.login.domain` + `client-id`;
    PKCE, sign-out at Touchque);
  - a resource-server `JwtDecoder` for at+jwt access tokens (`touchque.login.audience`);
  - MCP server protection (`touchque.mcp.*`), serving the RFC 9728 metadata.
