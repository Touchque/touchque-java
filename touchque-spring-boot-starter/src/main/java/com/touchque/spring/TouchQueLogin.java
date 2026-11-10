package com.touchque.spring;

import com.touchque.login.HostedLogin;
import java.util.Map;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * TouchQue Login (hosted sign-in) through Spring Security's OAuth2 login. With
 * {@code touchque.login.domain} and {@code touchque.login.client-id} set and no security chain of
 * your own, the starter signs every page in with it. In your own chain:
 *
 * <pre>{@code
 * @Bean
 * SecurityFilterChain web(HttpSecurity http, TouchQueLogin touchQueLogin) throws Exception {
 *     http.authorizeHttpRequests(a -> a.requestMatchers("/").permitAll().anyRequest().authenticated());
 *     touchQueLogin.configure(http);   // sign-in with PKCE at /oauth2/authorization/touchque, sign-out at TouchQue
 *     return http.build();
 * }
 * }</pre>
 */
public final class TouchQueLogin {
    private final ClientRegistrationRepository registrations;
    private final String registrationId;
    private final String postLogoutRedirectUri;

    public TouchQueLogin(ClientRegistrationRepository registrations, TouchQueProperties.Login login) {
        this.registrations = registrations;
        this.registrationId = login.getRegistrationId();
        this.postLogoutRedirectUri = login.getPostLogoutRedirectUri();
    }

    /**
     * The tenant's issuer URL for a domain ({@code acme.login.touchque.com} → https://acme.login.touchque.com);
     * http:// only on this machine ({@link HostedLogin#issuerOf}).
     */
    public static String issuer(String domain) {
        return HostedLogin.issuerOf(domain);
    }

    /** The Spring Security client registration of a TouchQue Login app (PKCE; HTTP Basic when it has a secret). */
    public static ClientRegistration registration(TouchQueProperties.Login login) {
        String issuer = issuer(login.getDomain());
        boolean confidential = login.getClientSecret() != null && !login.getClientSecret().isEmpty();
        return ClientRegistration.withRegistrationId(login.getRegistrationId())
                .clientName("TouchQue")
                .clientId(login.getClientId())
                .clientSecret(confidential ? login.getClientSecret() : null)
                .clientAuthenticationMethod(confidential ? ClientAuthenticationMethod.CLIENT_SECRET_BASIC : ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(login.getScope())
                .issuerUri(issuer)
                .authorizationUri(issuer + "/authorize")
                .tokenUri(issuer + "/oauth/token")
                .jwkSetUri(issuer + "/.well-known/jwks.json")
                .userInfoUri(issuer + "/userinfo")
                .userNameAttributeName("sub")
                .providerConfigurationMetadata(Map.of("end_session_endpoint", issuer + "/oidc/logout"))
                .build();
    }

    /**
     * OAuth2 login with PKCE (also for confidential apps), the callback's iss checked (RFC 9207, see
     * {@link TouchQueIssuerFilter}) and sign-out at TouchQue (RP-initiated logout).
     */
    public HttpSecurity configure(HttpSecurity http) throws Exception {
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(registrations, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        OidcClientInitiatedLogoutSuccessHandler logout = new OidcClientInitiatedLogoutSuccessHandler(registrations);
        logout.setPostLogoutRedirectUri(postLogoutRedirectUri);
        http.oauth2Login(o -> o.authorizationEndpoint(a -> a.authorizationRequestResolver(resolver)).loginPage("/oauth2/authorization/" + registrationId));
        http.addFilterBefore(new TouchQueIssuerFilter(registrations, registrationId), OAuth2LoginAuthenticationFilter.class);
        http.logout(l -> l.logoutSuccessHandler(logout));
        return http;
    }
}
