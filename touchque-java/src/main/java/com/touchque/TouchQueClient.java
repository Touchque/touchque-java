package com.touchque;

import com.touchque.flow.Approval;
import com.touchque.flow.CompleteExpectations;
import com.touchque.flow.StartOptions;
import com.touchque.flow.Step;
import com.touchque.flow.Steps;
import com.touchque.internal.TouchQueHttp;
import com.touchque.resources.ActionTypes;
import com.touchque.resources.Actions;
import com.touchque.resources.Agents;
import com.touchque.resources.Assist;
import com.touchque.resources.Auth;
import com.touchque.resources.Identity;
import com.touchque.resources.Login;
import com.touchque.resources.LoginRequestOptions;
import com.touchque.resources.Mobile;
import com.touchque.resources.Offline;
import com.touchque.resources.QrPairings;
import com.touchque.resources.DeviceRisk;
import com.touchque.resources.SafeGuard;
import com.touchque.resources.Recovery;
import com.touchque.resources.Risk;
import com.touchque.resources.WebAuthn;
import com.touchque.resources.Webhook;
import java.util.function.Supplier;

/**
 * The TouchQue client. Every call is signed with your API secret, so it belongs on your server;
 * browser pieces relay through it.
 *
 * <pre>{@code
 * // TQ_API_KEY=tq_...  TQ_API_SECRET=...
 * var tq = new TouchQueClient();
 * var step = tq.start("SEND_MONEY", new StartOptions("jane@acme.com").details(List.of(LoginDetail.of("Amount", "250 EUR"))));
 * }</pre>
 *
 * Thread-safe; create one and reuse it (in Spring Boot the starter makes it a bean).
 */
public final class TouchQueClient {
    public static final String DEFAULT_BASE_URL = TouchQueOptions.DEFAULT_BASE_URL;

    private final TouchQueHttp http;
    private final Auth auth;
    private final Login login;
    private final WebAuthn webauthn;
    private final Webhook webhook;
    private final Offline offline;
    private final ActionTypes actionTypes;
    private final Actions actions;
    private final Risk risk;
    private final Recovery recovery;
    private final Assist assist;
    private final Agents agents;
    private final Identity identity;
    private final Mobile mobile;
    private final QrPairings qrPairings;
    private final DeviceRisk deviceRisk;
    private final SafeGuard safeGuard;

    /** A client from the environment ({@code TQ_API_KEY}, {@code TQ_API_SECRET}, {@code TQ_API_URL}). */
    public TouchQueClient() {
        this(new TouchQueOptions());
    }

    /** @param options anything left null falls back to the environment */
    public TouchQueClient(TouchQueOptions options) {
        TouchQueOptions.Resolved r = options.resolve();
        this.http = new TouchQueHttp(r.apiKey(), r.apiSecret(), r.baseUrl(), r.timeout(), r.httpClient(), r.log());
        this.auth = new Auth(http);
        this.login = new Login(http);
        this.webauthn = new WebAuthn(http);
        this.webhook = new Webhook(r.apiSecret());
        this.offline = new Offline(http);
        this.actionTypes = new ActionTypes(http);
        this.actions = new Actions(http);
        this.risk = new Risk(http);
        this.recovery = new Recovery(http);
        this.assist = new Assist(http);
        this.agents = new Agents(http);
        this.identity = new Identity(http);
        this.mobile = new Mobile(http);
        this.qrPairings = new QrPairings(http);
        this.deviceRisk = new DeviceRisk(http);
        this.safeGuard = new SafeGuard(http);
    }

    /** Setup secrets and a user's link status. */
    public Auth auth() {
        return auth;
    }

    /** Push approvals: request, status, verify, use once, report fraud. */
    public Login login() {
        return login;
    }

    /** Passkeys (the backend half of the browser ceremonies). */
    public WebAuthn webauthn() {
        return webauthn;
    }

    /** Webhook signature verification. */
    public Webhook webhook() {
        return webhook;
    }

    /** Offline Sign: QR challenge and typed-code approvals with the phone offline. */
    public Offline offline() {
        return offline;
    }

    /** Action types: what users approve (LOGIN, SEND_MONEY…). */
    public ActionTypes actionTypes() {
        return actionTypes;
    }

    /** TouchQue Actions: your own code in the approval pipeline (deploy, test, dry run, logs). */
    public Actions actions() {
        return actions;
    }

    /** Silent sign-ins: should this sign-in ask the phone, and which browsers TouchQue knows. */
    public Risk risk() {
        return risk;
    }

    /** Never Locked Out: move a user whose phone is gone to a new phone, with colleagues vouching. */
    public Recovery recovery() {
        return recovery;
    }

    /** Help desk: IT working on a person's account in the open, and checks on their phone before sensitive actions. */
    public Assist assist() {
        return assist;
    }

    /** AI agents as identities of their own. The agent itself uses {@link com.touchque.agents.TouchQueAgent}. */
    public Agents agents() {
        return agents;
    }

    /** TouchQue Login: your customers' accounts, roles, organizations, apps, connections (Management API). */
    public Identity identity() {
        return identity;
    }

    /** Mobile SDK: your own iOS/Android app approves for your users. */
    public Mobile mobile() {
        return mobile;
    }

    /** Pairing a browser by QR code: the phone that scans it is the one asked to approve. */
    public QrPairings qrPairings() {
        return qrPairings;
    }

    /** Device risk: the device on your sign-up, reset, sign-in or approval page (a paid add-on). */
    public DeviceRisk deviceRisk() {
        return deviceRisk;
    }

    /** Safe Guard: Safe transactions approved on the approver's phone, for TouchQueSafeGuard. */
    public SafeGuard safeGuard() {
        return safeGuard;
    }

    /** Internal: the signed HTTP client. */
    public TouchQueHttp http() {
        return http;
    }

    /** Internal: signs the guard tokens. */
    public String apiSecret() {
        return http.apiSecret();
    }

    public String baseUrl() {
        return http.baseUrl();
    }

    /**
     * Starts an approval and returns at once: show the step in your UI. {@code waiting} with
     * {@code number}: show the number, the user picks it on the phone. {@code enroll}: show
     * {@code enroll.qrCodeDataUrl} so the user links the TouchQue app first.
     */
    public Step start(String action, StartOptions options) {
        return Steps.start(this, action, options);
    }

    /** Where a started approval is now: waiting, approved, rejected, expired… */
    public Step check(String requestId) {
        return Steps.check(this, requestId);
    }

    /**
     * Uses an approved request exactly once, after checking it is for this user, action and
     * transaction. Call it right before doing the protected thing.
     *
     * @throws TouchQueApprovalMismatchException the approval is for a different user, action or transaction
     * @throws TouchQueApiException             409 already_used, not_approved, rejected, expired or revoked
     */
    public Approval complete(String requestId, CompleteExpectations expect) {
        return Steps.complete(this, requestId, expect);
    }

    /** Runs {@code action} only after the user approved it on the phone (the push and the wait of {@code login().verify}). */
    public <T> T protect(LoginRequestOptions request, Supplier<T> action) {
        login.verify(request);
        return action.get();
    }
}
