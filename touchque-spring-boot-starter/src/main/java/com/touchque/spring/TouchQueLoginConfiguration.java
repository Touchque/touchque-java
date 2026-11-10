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

/** TouchQue Login sign-in through Spring Security (touchque.login.domain + client-id). */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(name = {"org.springframework.security.oauth2.client.registration.ClientRegistrationRepository",
        "org.springframework.security.config.annotation.web.builders.HttpSecurity"})
@ConditionalOnProperty(prefix = "touchque.login", name = {"domain", "client-id"})
class TouchQueLoginConfiguration {
    @Bean
    @ConditionalOnMissingBean
    ClientRegistrationRepository touchQueClientRegistrations(TouchQueProperties properties) {
        return new InMemoryClientRegistrationRepository(TouchQueLogin.registration(properties.getLogin()));
    }

    @Bean
    @ConditionalOnMissingBean
    TouchQueLogin touchQueLogin(ClientRegistrationRepository registrations, TouchQueProperties properties) {
        return new TouchQueLogin(registrations, properties.getLogin());
    }

    /** With no security chain of your own: every page signs in with TouchQue Login. */
    @Bean
    @ConditionalOnDefaultWebSecurity
    SecurityFilterChain touchQueSecurityFilterChain(HttpSecurity http, TouchQueLogin login) throws Exception {
        http.authorizeHttpRequests(a -> a.anyRequest().authenticated());
        login.configure(http);
        return http.build();
    }
}
