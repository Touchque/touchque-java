# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [4.2.0] — Unreleased

### Security
- **The offline approval-token check refuses another workspace's token.** `GET /agents/jwks.json` is one key set for every Touchque workspace, and the check used to compare `aud` only when you passed an audience, so a token Touchque signed for someone else's workspace (their own phone, any person's name, any details) could pass your executor. Now:
  - `agents().verifyApprovalToken(token, audience, expect)` (a null or empty audience) uses this workspace's own audience by default: `agents().approvalAudience()` asks `GET /agents/approval-audience` once (`touchque:workspace:<id>`) and keeps it.
  - `ApprovalToken.verifyWith(token, jwks, audience, expect, now)` requires the audience. A missing or empty one throws TouchQueApprovalMismatchException (`audience is required`).
  - A token without `aud` is refused (`the approval token names no workspace`), as is one for another workspace (`the approval token is for another workspace`).
  - Breaking for callers of the low-level function who passed no audience: pass agents().approvalAudience()'s value.
  - `redeemApproval` was already safe: Touchque compares `aud` with your workspace there.

### Added
- **`deviceRisk().searchEvents(new DeviceRisk.SearchOptions()...)`: search your workspace's Device risk identifications**, newest first, one page at a time (`GET /device-risk/events`): `from`/`to` (7 days by default, at most 90, within your retention), `signal`, `stepUp`, `kind`, `origin`, `ip` (an address or a CIDR range; never returned), `account`, `visitorId`, `requestId`, `limit` (1 to 100) and the opaque `cursor` from the previous page's `nextCursor`. `DeviceRisk.SearchResult` record.
- `DeviceRisk.CheckResult.engine()` (String, null when absent): the engine's state for this check; `"unavailable"` when the risk engine could not be reached and the verdict is a safe default (`stepUp` true), so an outage can be told apart from risk. The 15-argument constructor stays.
- **`webauthn().primaryAvailability()`: is passkey sign-in on for your workspace?** `GET /webauthn/authenticate/primary/availability` answers `enabled` and `userVerification` (`required` or `preferred`, null when off). Ask before your sign-in page shows its passkey button and passkey autofill; when it is off, `primaryOptions` answers 403 `passwordless_login_disabled`.
- **Shared Signals: receive the security events an identity provider sends after sign-in.** TouchQue SSO sends Security Event Tokens (OpenID Shared Signals Framework 1.0) for an organization's members to the receivers its admin adds (Organization > Continuous access): CAEP `session-revoked`, `credential-change`, `device-compliance-change`, RISC `account-disabled`, `credential-compromise`; `txn` carries the case code of TouchQue's decision. `new SecurityEventVerifier(new SecurityEventVerifier.Options(issuer, audience).jwksUri(…).jwks(…).clockSkew(…)).verify(token)` returns a `SecurityEvent` record (`jti`, `issuer`, `audience`, `issuedAt`, `txn`, `subject`, `type`, `name`, `claims`) or throws `TouchQueSecurityEventException` with the RFC 8935 code to answer in `error()` (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`); `SecurityEventVerifier.poll(new PollOptions(url, token).ack(…).maxEvents(…))` for poll delivery (RFC 8936); `SecurityEventVerifier.TYPES`. The keys come from the issuer's `/.well-known/ssf-configuration`; a SET does not expire, so keep the jtis you handled. Tested against the shared vectors (`fixtures/security-event-vectors.json`).
- **Safe Guard: Safe transactions approved on the approver's phone, for TouchQueSafeGuard.** `tq.safeGuard().request(new SafeGuard.RequestOptions(externalUsername, type, safeTx))` sends the raw transaction (`SafeTx`, fluent; the phone decodes it itself and signs with a key only its biometrics unlock), `status(requestId)` and `waitForApproval(requestId, timeout, pollInterval)` hand back the 105-byte approval. `SafeApproval.verify(tx, approval, approverKey, new SafeApproval.VerifyOptions().purpose(…).approverIndex(…).rows(…) | displayDigest(…).now(…))` checks it the way the guard does, without trusting TouchQue: the Safe transaction hash (EIP-712, Keccak-256 here) and the governance hash computed here, the 149-byte message, low `s`, the one-day expiry window, the P-256 signature. `SafeApproval.withApprovals(ownerSignatures, approvals)` for `execTransaction`, `SafeApproval.scheduleCall(safe, governanceHash, approvals)` for a governance change; `safeTxHash`, `governanceHash`, `message`, `displayDigest`. Tested against the shared vectors (`fixtures/safe-guard-vectors.json`).
- **Opt-in logging, silent by default.** `new TouchQueOptions().logger(System.Logger)` receives the SDK's own problems: a misconfigured guard (500 `misconfigured`), an `onChallenge` that threw, a relay error (502 `relay_error`, 503 `2FA_UNAVAILABLE`) or a relay without `getLoginUser`, a silent sign-in check that failed (the guard then asks the phone), and an unexpected error behind a guard's 503. `debug(true)` with no logger writes them to System.Logger `touchque`; neither set, nothing is logged. No new dependency. Lines carry an error's class, code and message, never the error object, a request or a user, and a logger that throws never breaks a request. Spring Boot: `touchque.debug=true` (the `touchque` logger reaches Spring Boot's logging through its java.util.logging bridge).
- **Webhook events of Never Locked Out and the help desk** (`Webhook.EVENT_RECOVERY_*`, `Webhook.EVENT_ASSIST_*`), the names the API sends: `RECOVERY_STARTED`, `RECOVERY_DEVICE_BOUND`, `RECOVERY_COOLING`, `RECOVERY_COMPLETED`, `RECOVERY_VETOED`, `RECOVERY_EXPIRED`, `RECOVERY_FAILED`; `ASSIST_OPENED`, `ASSIST_ENDED`, `ASSIST_CHECK_PASSED`, `ASSIST_CHECK_FAILED`, `ASSIST_UNFROZEN`, `ASSIST_CLAIM_CONFIRMED`, `ASSIST_CLAIM_UNVERIFIED` (someone pretended to be IT).
- **Shared Signals: discovery and polling tested, and a README section.** The keys found through the issuer's `/.well-known/ssf-configuration` and `SecurityEventVerifier.poll` are tested against a local transmitter (the Node SDK's cases, plus metadata for another issuer and a refused poll); the README's "Shared Signals (security events from Touchque SSO)" shows verifying a pushed SET and polling.

### Fixed
- **Spring webhook endpoint: a delivery your listener failed on is handled when Touchque retries it.** When the `TouchQueWebhookListener` throws, the endpoint still answers 500 and now releases the delivery's `jti` (`Webhook.ReplayCache.release`, a new default method that `MemoryReplayCache` implements), so the retry runs the listener again instead of being answered 200 as a duplicate and lost. A `ReplayCache` of your own should implement `release` (Redis `DEL`).
- Usernames, emails, HTTP methods, content types, offline codes and IBANs are case-folded with `Locale.ROOT`. In a Turkish or Azerbaijani default locale, `Ilker@acme.com` became `ılker@acme.com`, and the relay pushed to, or offered first-time linking for, a user that does not exist.
- `complete()` and the guard treat an empty `referenceId` like none, as the API stores it: an approval started with `referenceId("")` was consumed and then refused as a mismatch. A mismatch after the approval in `Guard.run` (and so in `@RequireTouchQue` and the relay) is now a 503 `unavailable` answer, as in the other SDKs, instead of an exception.
- Transaction details are trimmed the way the API trims them (JavaScript's `trim`): a label or value with a leading or trailing NBSP, U+FEFF, U+2028 or ideographic space gave another digest, so `complete()` refused a genuine approval and `ApprovalProof.verify` returned false.

### Security
- **Hosted login checks `iss` everywhere (RFC 9207).** `HostedLogin.handleCallback` now also refuses an empty `iss=` (`issuer_mismatch`), and the Spring Boot starter's `TouchQueLogin.configure(http)` adds a filter before Spring Security's callback, which reads only code, state and the error fields: a foreign or empty `iss` gets 400 `issuer_mismatch` before the code is exchanged and drops that pending sign-in. A callback without `iss` (a server that does not send it yet) is still accepted.
- **`SafeApproval.verify` without `purpose` accepts only an ordinary approval (`approve`).** A governance approval (`schedule`) passes only when you name `purpose("schedule")`. Before, a schedule approval, which carries no Safe nonce and only starts the guard's waiting time, also came back valid, so a co-signer that executes on `valid()` could execute on it.
- `HostedLogin`, `MyAccount` and the starter's Touchque Login (`touchque.login.domain`) refuse a plaintext `http://` domain except on this machine (localhost, 127.0.0.1, ::1, `*.localhost`), like the API `baseUrl`: codes, PKCE verifiers, the client secret and tokens would otherwise travel in the clear. `HostedLogin.issuerOf` is public.

## [4.1.0] — Unreleased

### Added
- **Device risk events like a device-intelligence event, without raw traits:** `deviceRisk.check` and `getEvent` answers carry `network()`, `velocity()` and `bot()`: the address as the risk engine saw it (country, region, city, never coordinates; the operator; `type` isp, hosting or tor; `timezoneMismatch` when the browser's clock does not fit the address), the visitor's counts (accounts, sign-ups, countries, stored-id resets, identifications in the last hour and day) and one answer to "a bot?" (`detected`, `suspected` or `not_detected`, with reasons). The field the script tag fills may now carry its pointer summary after the requestId: pass it as it came.

### Changed
- `TouchQueApprovalMismatchException` does not name the other person in its message (the SDK writes nothing to any log).

### Added
- **A code typed back on the phone:** `LoginRequestOptions.reply(key, channel, target)`; `CodeReply.newKey()` and `CodeReply.open(privateKey, requestId, ct)` open `status(id).reply().get("ct")`.
- **Feature errors:** a feature your organization cannot use here (403 `feature_not_in_plan`, `feature_read_only`, `feature_off`) throws `TouchQueFeatureNotInPlanException`, `TouchQueFeatureReadOnlyException` or `TouchQueFeatureOffException`, all `TouchQueFeatureException` (`feature()`, `featureReason()`) and still `TouchQueApiException`.

First release of the Java SDK and the Spring Boot starter, at the same surface as the Node,
Python, PHP, Go, .NET and Ruby SDKs 4.1.0.

### Added
- **Webhook events `DEVICE_RISK_SIGNAL` and `DEVICE_RISK_ALERT`** (`Webhook.EVENT_DEVICE_RISK_*`): a Device risk signal that asks for more (identifiers, signals and the engine's verdict, never a trait), and an alert rule of the workspace that went off. Signed like every event.
- **Device risk in one line: `tq.deviceRisk().check(request.getParameter("touchque_request_id"))`** (or `check(CheckOptions.ofRequest(…).event("sign_up").externalUsername(email))`) with the script tag (`device.js`, `@touchque/web` 1.6.0), which fills that field. Pass it as it came: null, empty, made up or expired is still a verdict (`report` missing, unknown, expired, invalid; the signal `device_identification_missing`, a number-matched step-up at most), never an exception. `DeviceRisk.REPORTS`.
- **Device risk: `tq.deviceRisk().check(DeviceRisk.CheckOptions.ofRequest(requestId).event("sign_up")...)` and `tq.deviceRisk().getEvent(requestId)`** (a paid add-on; 409 `device_risk_off` until the workspace turns it on), and `deviceRiskRequestId(...)` (or `deviceRisk(...)`) on `LoginRequestOptions` and `Risk.CheckOptions`. The page's requestId comes from `@touchque/web` `deviceRisk.identify`. Every signal only ever asks for more (`stepUp`, never a refusal); signals start in shadow. `DeviceRisk.parseCheck`, `DeviceRisk.EVENTS`.
- **`com.touchque:touchque-java`** (Java 17+, `java.net.http`, Jackson, unchecked exceptions, no logging):
  - `TouchQueClient` with these resources:
    - `auth()` and `login()` (request, status, `verify` with `onChallenge`, `consume`, `reportFraud`, recovery codes);
    - `webauthn()`;
    - `offline()` (QR and typed codes, outage verifiers);
    - `risk()` (silent sign-ins);
    - `actionTypes()` (Second Thought questions) and `actions()` (TouchQue Actions and their secrets);
    - `recovery()` (Never Locked Out) and `assist()` (help desk);
    - `agents()` (the token vault, mandates, blocks, the kill switch, the workspace policy, agent events, approval tokens);
    - `identity()` (the TouchQue Login Management API, including `clients().rotateSecret`, `users().endSession` and `exports().file`);
    - `mobile()` (the Mobile SDK's server side, `Mobile.pushFromWebhook`);
    - `qrPairings()`;
    - `webhook()` (signature, timestamp window, replay cache).
  - `start` / `check` / `complete`, `protect` and `Guard.run`: the two-phase step-up contract
    shared by every TouchQue server SDK. It covers offline codes, silent sign-ins, Vishing Shield
    (provisional approvals, passkey step-up), Mirror Alarm canaries and "Why?" case codes.
  - `RelayHandler<T>`: the routes `@touchque/web` calls, framework-neutral, with rate limits
    (`RateLimit.Store`).
- **Pairing a browser by QR code: `tq.qrPairings()`.**
  - `create(new QrPairings.CreateOptions(keyThumbprint).clientIp(…).userAgent(…).browser(…).os(…).ttlSeconds(…))`
    returns `uri` (`touchque://pair-browser?...`) to show as a QR code. The nonce stays with you;
    TouchQue keeps only its hash.
  - `get` says who scanned the QR and how near the phone was (`proximity`).
  - `refuse` tells the phone why your own checks said no.
  - `LoginRequestOptions.qrPairing` asks the phone that scanned, once, with number matching.
- **AI agents:**
  - `AgentKeys` (ES256 and EdDSA, RFC 7638 thumbprints).
  - `TouchQueAgent`: the agent's own private_key_jwt + DPoP client, with `requestApproval`,
    `requireApproval`, `waitForApproval`, mandates and the token vault.
  - `TouchQueOrgAgent`: an organization's agent on TouchQue SSO. DPoP tokens, token exchange,
    CIBA, the token vault, shared accounts, and GitHub Actions or file tokens instead of a key.
  - `McpAuth` for an MCP server whose authorization server is TouchQue SSO.
  - `ApprovalToken` checks and `ApprovalProof.verify`.
- **Cross App Access (ID-JAG) and A2A agent cards:**
  - `CrossAppAccess.requestIdJag` / `redeemIdJag`.
  - `IdJagVerifier`: checks typ, issuer, single audience, client and expiry, and uses each ID-JAG
    once (`firstUse` for a shared store).
  - `AgentCard.verify` / `sign` / `canonicalJson` (RFC 8785).
- **TouchQue Login:**
  - `HostedLogin`: an OpenID Connect client with PKCE, ID token checks (nonce, at_hash), refresh,
    token exchange, CIBA, the token vault, client credentials, logout and `verifyAccessToken`.
  - `MyAccount`: the customer's own account API, with step-up errors.
  - `LoginSession`: encrypted cookies, in the same format as the Node and Ruby SDKs.
- **`com.touchque:touchque-spring-boot-starter`** (Spring Boot 3):
  - the `TouchQueClient` bean from `touchque.*`, then the environment;
  - `@RequireTouchQue("ACTION")` on controller methods or classes: a 202 step until the phone
    approves, then the method runs once, with an `Approval` parameter. Per-action
    `TouchQueGuardOptions` beans set details, the user, context and silent sign-ins.
  - the relay routes at `touchque.relay.path`, with a `RelayOptions<HttpServletRequest>` bean;
  - verified webhooks at `touchque.webhook.path`, with a `TouchQueWebhookListener` bean
    (401 on a bad signature, 200 `duplicate` on a replay);
  - TouchQue Login through Spring Security OAuth2 login (`touchque.login.domain` + `client-id`;
    PKCE, sign-out at TouchQue);
  - a resource-server `JwtDecoder` for at+jwt access tokens (`touchque.login.audience`);
  - MCP server protection (`touchque.mcp.*`), serving the RFC 9728 metadata.
