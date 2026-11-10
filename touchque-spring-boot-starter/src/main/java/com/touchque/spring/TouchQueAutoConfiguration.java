package com.touchque.spring;

import com.touchque.TouchQueClient;
import com.touchque.TouchQueOptions;
import com.touchque.agents.McpAuth;
import com.touchque.flow.Approval;
import com.touchque.relay.RelayHandler;
import com.touchque.relay.RelayOptions;
import com.touchque.resources.Webhook;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * TouchQue for Spring Boot: the {@link TouchQueClient} bean (from {@code touchque.*}, then the
 * environment), {@link RequireTouchQue} on controller methods, the relay routes (with a
 * {@code RelayOptions<HttpServletRequest>} bean), verified webhooks (with a
 * {@link TouchQueWebhookListener} bean), TouchQue Login through Spring Security
 * ({@code touchque.login.*}) and MCP server protection ({@code touchque.mcp.*}).
 */
@AutoConfiguration(before = {OAuth2ClientAutoConfiguration.class, OAuth2ResourceServerAutoConfiguration.class, SecurityAutoConfiguration.class})
@EnableConfigurationProperties(TouchQueProperties.class)
@Import({TouchQueLoginConfiguration.class, TouchQueResourceServerConfiguration.class})
public class TouchQueAutoConfiguration {
    /** Created on first use, so an app that only uses TouchQue Login needs no API key. */
    @Bean
    @Lazy
    @ConditionalOnMissingBean
    public TouchQueClient touchQueClient(TouchQueProperties properties) {
        return new TouchQueClient(new TouchQueOptions().apiKey(properties.getApiKey()).apiSecret(properties.getApiSecret())
                .baseUrl(properties.getBaseUrl()).timeout(properties.getTimeout()).debug(properties.isDebug()));
    }

    /** In-process replay protection for webhooks; with several instances, declare a shared one (Redis SET NX, and DEL in release). */
    @Bean
    @ConditionalOnMissingBean
    public Webhook.ReplayCache touchQueWebhookReplayCache() {
        return new Webhook.MemoryReplayCache();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "touchque.mcp", name = {"issuer", "resource"})
    public McpAuth touchQueMcpAuth(TouchQueProperties properties) {
        TouchQueProperties.Mcp mcp = properties.getMcp();
        return new McpAuth(new McpAuth.Options(mcp.getIssuer(), mcp.getResource()).tools(mcp.getTools()).resourceName(mcp.getResourceName()));
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass(name = "org.springframework.web.servlet.DispatcherServlet")
    static class Web {
        @Bean
        static TouchQueGuardPostProcessor touchQueGuardPostProcessor(ObjectProvider<TouchQueClient> client, ObjectProvider<TouchQueGuardOptions> options) {
            return new TouchQueGuardPostProcessor(client, options);
        }

        @Bean
        TouchQueExceptionHandler touchQueExceptionHandler() {
            return new TouchQueExceptionHandler();
        }

        /** An {@link Approval} parameter of a {@link RequireTouchQue} method receives the approval. */
        @Bean
        WebMvcConfigurer touchQueWebMvcConfigurer() {
            return new WebMvcConfigurer() {
                @Override
                public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
                    resolvers.add(new HandlerMethodArgumentResolver() {
                        @Override
                        public boolean supportsParameter(MethodParameter parameter) {
                            return Approval.class.equals(parameter.getParameterType());
                        }

                        @Override
                        public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mav, NativeWebRequest request, WebDataBinderFactory binders) {
                            HttpServletRequest http = request.getNativeRequest(HttpServletRequest.class);
                            return http == null ? null : TouchQueSpring.approval(http);
                        }
                    });
                }
            };
        }

        /** Before Spring Security: the signature is the webhook's authentication. */
        @Bean
        @ConditionalOnBean(TouchQueWebhookListener.class)
        FilterRegistrationBean<TouchQueWebhookFilter> touchQueWebhookFilter(TouchQueClient client, Webhook.ReplayCache cache, TouchQueWebhookListener listener,
                TouchQueProperties properties) {
            TouchQueProperties.Webhook w = properties.getWebhook();
            FilterRegistrationBean<TouchQueWebhookFilter> bean = new FilterRegistrationBean<>(
                    new TouchQueWebhookFilter(client, cache, listener, w.getPath(), (int) w.getTolerance().getSeconds()));
            bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
            bean.setName("touchQueWebhookFilter");
            return bean;
        }

        /** After Spring Security: the relay's callbacks see the signed-in user. */
        @Bean
        @ConditionalOnBean(RelayOptions.class)
        FilterRegistrationBean<TouchQueRelayFilter> touchQueRelayFilter(TouchQueClient client, ObjectProvider<RelayOptions<HttpServletRequest>> options,
                TouchQueProperties properties) {
            FilterRegistrationBean<TouchQueRelayFilter> bean = new FilterRegistrationBean<>(
                    new TouchQueRelayFilter(new RelayHandler<>(client, options.getObject()), properties.getRelay().getPath()));
            bean.setOrder(0);
            bean.setName("touchQueRelayFilter");
            return bean;
        }

        /** Before Spring Security: an MCP request carries its own TouchQue token. */
        @Bean
        @ConditionalOnProperty(prefix = "touchque.mcp", name = {"issuer", "resource"})
        FilterRegistrationBean<TouchQueMcpFilter> touchQueMcpFilter(McpAuth auth, TouchQueProperties properties) {
            List<String> paths = properties.getMcp().getPaths();
            if (paths.isEmpty()) {
                String p = URI.create(properties.getMcp().getResource()).getRawPath();
                paths = List.of(p == null || p.isEmpty() ? "/" : p);
            }
            FilterRegistrationBean<TouchQueMcpFilter> bean = new FilterRegistrationBean<>(new TouchQueMcpFilter(auth, paths));
            bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 20);
            bean.setName("touchQueMcpFilter");
            return bean;
        }
    }
}
