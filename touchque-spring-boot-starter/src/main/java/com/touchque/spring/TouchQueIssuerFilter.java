package com.touchque.spring;

import com.touchque.internal.Json;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * RFC 9207 at the sign-in callback ({@code /login/oauth2/code/{registrationId}}). Spring Security
 * reads only the code, state and error fields of the answer, so this filter runs before it: an
 * answer that carries {@code iss} (even an empty one) must name the registration's issuer, error
 * answers too. Otherwise it answers 400 {@code {"error":"issuer_mismatch"}} before the code is
 * exchanged, and the pending sign-in in the session is dropped. An answer without {@code iss}
 * (a server that does not send it yet) goes on to Spring Security.
 */
final class TouchQueIssuerFilter extends OncePerRequestFilter {
    private final ClientRegistrationRepository registrations;
    private final String registrationId;
    private final String callbackPath;
    private final HttpSessionOAuth2AuthorizationRequestRepository pending = new HttpSessionOAuth2AuthorizationRequestRepository();

    TouchQueIssuerFilter(ClientRegistrationRepository registrations, String registrationId) {
        this.registrations = registrations;
        this.registrationId = registrationId;
        this.callbackPath = "/login/oauth2/code/" + registrationId;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String iss = request.getParameter("iss");
        if (iss != null && callbackPath.equals(Responses.path(request))) {
            ClientRegistration registration = registrations.findByRegistrationId(registrationId);
            String issuer = registration == null ? null : registration.getProviderDetails().getIssuerUri();
            if (issuer != null && !issuer.equals(iss)) {
                pending.removeAuthorizationRequest(request, response);
                Responses.json(response, HttpServletResponse.SC_BAD_REQUEST, Json.object().put("error", "issuer_mismatch")
                        .put("error_description", iss.isEmpty() ? "The response has an empty iss" : "The response came from " + iss));
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
