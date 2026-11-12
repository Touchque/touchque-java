package com.touchque.spring;

import com.touchque.TouchqueClient;
import com.touchque.TouchqueOptions;
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
 * Touchque for Spring Boot: the {@link TouchqueClient} bean (from {@code touchque.*}, then the
 * environment), {@link RequireTouchque} on controller methods, the relay routes (with a
 * {@code RelayOptions<HttpServletRequest>} bean), verified webhooks (with a
 * {@link TouchqueWebhookListener} bean), Touchque Login through Spring Security
 * ({@code touchque.login.*}) and MCP server protection ({@code touchque.mcp.*}).
 */
@AutoConfiguration(before = {OAuth2ClientAutoConfiguration.class, OAuth2ResourceServerAutoConfiguration.class, SecurityAutoConfiguration.class})
@EnableConfigurationProperties(TouchqueProperties.class)
@Import({TouchqueLoginConfiguration.class, TouchqueResourceServerConfiguration.class})
public class TouchqueAutoConfiguration {
    /**
     * Created on first use, so an app that only uses Touchque Login needs no API key. Without one,
     * {@link RequireTouchque} methods answer 500 {@code misconfigured} instead of failing the app.
     */
    @Bean
    @Lazy
    @ConditionalOnMissingBean
    public TouchqueClient touchqueClient(TouchqueProperties properties) {
        return new TouchqueClient(new TouchqueOptions().apiKey(properties.getApiKey()).apiSecret(properties.getApiSecret())
                .baseUrl(properties.getBaseUrl()).timeout(properties.getTimeout()).debug(properties.isDebug()));
    }

    /** In-process replay protection for webhooks; with several instances, declare a shared one (Redis SET NX, and DEL in release). */
    @Bean
    @ConditionalOnMissingBean
    public Webhook.ReplayCache touchqueWebhookReplayCache() {
        return new Webhook.MemoryReplayCache();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "touchque.mcp", name = {"issuer", "resource"})
    public McpAuth touchqueMcpAuth(TouchqueProperties properties) {
        TouchqueProperties.Mcp mcp = properties.getMcp();
        return new McpAuth(new McpAuth.Options(mcp.getIssuer(), mcp.getResource()).tools(mcp.getTools()).resourceName(mcp.getResourceName()));
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass(name = "org.springframework.web.servlet.DispatcherServlet")
    static class Web {
        @Bean
        static TouchqueGuardPostProcessor touchqueGuardPostProcessor(ObjectProvider<TouchqueClient> client, ObjectProvider<TouchqueGuardOptions> options) {
            return new TouchqueGuardPostProcessor(client, options);
        }

        @Bean
        TouchqueExceptionHandler touchqueExceptionHandler() {
            return new TouchqueExceptionHandler();
        }

        /** An {@link Approval} parameter of a {@link RequireTouchque} method receives the approval. */
        @Bean
        WebMvcConfigurer touchqueWebMvcConfigurer() {
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
                            return http == null ? null : TouchqueSpring.approval(http);
                        }
                    });
                }
            };
        }

        /** Before Spring Security: the signature is the webhook's authentication. */
        @Bean
        @ConditionalOnBean(TouchqueWebhookListener.class)
        FilterRegistrationBean<TouchqueWebhookFilter> touchqueWebhookFilter(TouchqueClient client, Webhook.ReplayCache cache, TouchqueWebhookListener listener,
                TouchqueProperties properties) {
            TouchqueProperties.Webhook w = properties.getWebhook();
            FilterRegistrationBean<TouchqueWebhookFilter> bean = new FilterRegistrationBean<>(
                    new TouchqueWebhookFilter(client, cache, listener, w.getPath(), (int) w.getTolerance().getSeconds()));
            bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
            bean.setName("touchqueWebhookFilter");
            return bean;
        }

        /** After Spring Security: the relay's callbacks see the signed-in user. */
        @Bean
        @ConditionalOnBean(RelayOptions.class)
        FilterRegistrationBean<TouchqueRelayFilter> touchqueRelayFilter(TouchqueClient client, ObjectProvider<RelayOptions<HttpServletRequest>> options,
                TouchqueProperties properties) {
            FilterRegistrationBean<TouchqueRelayFilter> bean = new FilterRegistrationBean<>(
                    new TouchqueRelayFilter(new RelayHandler<>(client, options.getObject()), properties.getRelay().getPath()));
            bean.setOrder(0);
            bean.setName("touchqueRelayFilter");
            return bean;
        }

        /** Before Spring Security: an MCP request carries its own Touchque token. */
        @Bean
        @ConditionalOnProperty(prefix = "touchque.mcp", name = {"issuer", "resource"})
        FilterRegistrationBean<TouchqueMcpFilter> touchqueMcpFilter(McpAuth auth, TouchqueProperties properties) {
            List<String> paths = properties.getMcp().getPaths();
            if (paths.isEmpty()) {
                String p = URI.create(properties.getMcp().getResource()).getRawPath();
                paths = List.of(p == null || p.isEmpty() ? "/" : p);
            }
            FilterRegistrationBean<TouchqueMcpFilter> bean = new FilterRegistrationBean<>(new TouchqueMcpFilter(auth, paths));
            bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 20);
            bean.setName("touchqueMcpFilter");
            return bean;
        }
    }
}
