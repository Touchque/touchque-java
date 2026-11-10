package com.touchque.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.touchque.Assurance;
import com.touchque.RiskReason;
import java.util.List;

/**
 * An approval used once: run the protected action now. {@code confirmedVia}: DEVICE, WEBAUTHN,
 * OFFLINE_CODE, OFFLINE_TOTP or SILENT. {@code approvalProof}: the phone's signature over what it
 * showed ({@link com.touchque.crypto.ApprovalProof}). {@code provisional}: Vishing Shield, approved
 * during a call; let the user in, but treat the session as limited: critical actions are refused
 * until APPROVAL_RECONFIRMED, and APPROVAL_REVOKED means end it. {@code reasons}: silent sign-ins,
 * why TouchQue let this known browser in (nothing went to the phone).
 */
public record Approval(String requestId, String user, String action, Assurance assurance, String confirmedVia, JsonNode approvalProof,
                       Boolean provisional, Boolean revoked, String revokeReason, String reconfirmedAt, List<RiskReason> reasons) {
}
