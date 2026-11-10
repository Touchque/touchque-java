package com.touchque.spring;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Your API's TouchQue Login access tokens (touchque.login.domain + audience): a {@link JwtDecoder}
 * for Spring Security's resource server that checks the tenant's keys (RS256), typ at+jwt, the
 * issuer, expiry and that aud names your API. Scopes become SCOPE_ authorities as usual.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(name = "org.springframework.security.oauth2.jwt.NimbusJwtDecoder")
@ConditionalOnProperty(prefix = "touchque.login", name = {"domain", "audience"})
class TouchQueResourceServerConfiguration {
    @Bean
    @ConditionalOnMissingBean
    JwtDecoder touchQueJwtDecoder(TouchQueProperties properties) {
        return jwtDecoder(properties.getLogin().getDomain(), properties.getLogin().getAudience());
    }

    static NimbusJwtDecoder jwtDecoder(String domain, String audience) {
        String issuer = TouchQueLogin.issuer(domain);
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(issuer + "/.well-known/jwks.json")
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .jwtProcessorCustomizer(p -> p.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt"))))
                .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<List<String>>("aud", aud -> aud != null && aud.contains(audience))));
        return decoder;
    }
}
