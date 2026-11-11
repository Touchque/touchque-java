package com.touchque.spring;

import com.touchque.TouchqueMcpAuthException;
import com.touchque.agents.McpAuth;
import com.touchque.internal.Json;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * An MCP server whose authorization server is Touchque SSO: serves the RFC 9728 metadata at
 * {@link McpAuth#metadataPaths()} and checks the Touchque token (and its DPoP proof) of every
 * request to the MCP paths, answering 401/403 with {@code WWW-Authenticate}. The claims are in
 * {@link TouchqueSpring#mcpClaims}; check a tool with {@code mcpAuth.requireTool(claims, tool)}
 * (a refusal becomes a 403 too). Behind a proxy, set {@code server.forward-headers-strategy}: the
 * DPoP proof names the URL the client called.
 */
public class TouchqueMcpFilter extends OncePerRequestFilter {
    private final McpAuth auth;
    private final List<String> paths;

    public TouchqueMcpFilter(McpAuth auth, List<String> paths) {
        this.auth = auth;
        this.paths = List.copyOf(paths);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = Responses.path(request);
        return !paths.contains(path) && !auth.metadataPaths().contains(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String path = Responses.path(request);
        if (auth.metadataPaths().contains(path) && !paths.contains(path)) {
            if ("GET".equals(request.getMethod()) || "HEAD".equals(request.getMethod())) {
                Responses.json(response, 200, auth.protectedResourceMetadata());
            } else {
                Responses.error(response, 405, "method_not_allowed");
            }
            return;
        }
        try {
            request.setAttribute(TouchqueSpring.MCP_CLAIMS_ATTRIBUTE, auth.verify(request.getMethod(), request.getRequestURL().toString(), request::getHeader));
        } catch (TouchqueMcpAuthException e) {
            response.setHeader("WWW-Authenticate", e.wwwAuthenticate());
            Responses.json(response, e.status(), Json.object().put("error", e.error()).put("error_description", e.getMessage()));
            return;
        }
        chain.doFilter(request, response);
    }
}
