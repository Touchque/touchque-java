package com.touchque.spring;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.ConditionalOnDefaultWebSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

/** Touchque Login sign-in through Spring Security (touchque.login.domain + client-id). */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(name = {"org.springframework.security.oauth2.client.registration.ClientRegistrationRepository",
        "org.springframework.security.config.annotation.web.builders.HttpSecurity"})
@ConditionalOnProperty(prefix = "touchque.login", name = {"domain", "client-id"})
class TouchqueLoginConfiguration {
    @Bean
    @ConditionalOnMissingBean
    ClientRegistrationRepository touchqueClientRegistrations(TouchqueProperties properties) {
        return new InMemoryClientRegistrationRepository(TouchqueLogin.registration(properties.getLogin()));
    }

    @Bean
    @ConditionalOnMissingBean
    TouchqueLogin touchqueLogin(ClientRegistrationRepository registrations, TouchqueProperties properties) {
        return new TouchqueLogin(registrations, properties.getLogin());
    }

    /** With no security chain of your own: every page signs in with Touchque Login. */
    @Bean
    @ConditionalOnDefaultWebSecurity
    SecurityFilterChain touchqueSecurityFilterChain(HttpSecurity http, TouchqueLogin login) throws Exception {
        http.authorizeHttpRequests(a -> a.anyRequest().authenticated());
        login.configure(http);
        return http.build();
    }
}
