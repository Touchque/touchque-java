package com.touchque.spring;

import com.touchque.agents.McpAuth;
import com.touchque.flow.Approval;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Locale;
import org.springframework.util.ClassUtils;

/** Request helpers shared by the starter's pieces. */
public final class TouchQueSpring {
    /** Request attribute holding the {@link Approval} set by {@link RequireTouchQue}. */
    public static final String APPROVAL_ATTRIBUTE = "com.touchque.approval";
    /** Request attribute holding the checked {@link McpAuth.Claims} of an MCP request. */
    public static final String MCP_CLAIMS_ATTRIBUTE = "com.touchque.mcpClaims";

    private static final boolean SECURITY = ClassUtils.isPresent("org.springframework.security.core.Authentication", TouchQueSpring.class.getClassLoader());

    private TouchQueSpring() {
    }

    /** The approval of the current request (set by {@link RequireTouchQue}), or null. */
    public static Approval approval(HttpServletRequest request) {
        return request.getAttribute(APPROVAL_ATTRIBUTE) instanceof Approval a ? a : null;
    }

    /** The checked MCP token of the current request (set by the MCP filter), or null. */
    public static McpAuth.Claims mcpClaims(HttpServletRequest request) {
        return request.getAttribute(MCP_CLAIMS_ATTRIBUTE) instanceof McpAuth.Claims c ? c : null;
    }

    /** The signed-in user as TouchQue knows them: the email claim, else sub, else the principal's name. */
    public static String user(HttpServletRequest request) {
        Principal p = request.getUserPrincipal();
        if (p == null) return null;
        String fromClaims = SECURITY ? SecurityUsers.of(p) : null;
        return fromClaims != null ? fromClaims : p.getName();
    }

    /**
     * The END user's IP (IPv4-mapped addresses as IPv4). Behind a proxy, set
     * {@code server.forward-headers-strategy} so the container sees the real address.
     */
    public static String clientIp(HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        if (ip == null) return null;
        String lower = ip.toLowerCase(Locale.ROOT);
        if (lower.startsWith("::ffff:") && ip.indexOf('.') > 0) return ip.substring(7);
        if (lower.startsWith("0:0:0:0:0:ffff:") && ip.indexOf('.') > 0) return ip.substring(15);
        return ip;
    }
}
