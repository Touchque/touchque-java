package com.touchque.spring;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code touchque.*} settings. Anything left out falls back to the environment
 * ({@code TQ_API_KEY}, {@code TQ_API_SECRET}, {@code TQ_API_URL}).
 */
@ConfigurationProperties(prefix = "touchque")
public class TouchQueProperties {
    /** Your API key from the dashboard (tq_…). */
    private String apiKey;
    /** Your API secret: signs every request and verifies webhooks. Never send it to a browser or an app. */
    private String apiSecret;
    /** The API's address (default https://api.touchque.com; plain http only for localhost). */
    private String baseUrl;
    /** Timeout of one API request. */
    private Duration timeout = Duration.ofSeconds(10);
    /**
     * Log the SDK's own problems (a misconfigured guard, an onChallenge that threw, relay errors, a
     * failed silent sign-in check) to the logger {@code touchque}. Spring Boot's logging receives it
     * through its java.util.logging bridge; set its level with {@code logging.level.touchque}.
     * Default false: the SDK logs nothing.
     */
    private boolean debug;
    private final Relay relay = new Relay();
    private final Webhook webhook = new Webhook();
    private final Login login = new Login();
    private final Mcp mcp = new Mcp();

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getApiSecret() {
        return apiSecret;
    }

    public void setApiSecret(String apiSecret) {
        this.apiSecret = apiSecret;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public Duration getTimeout() {
        return timeout;
    }

    public void setTimeout(Duration timeout) {
        this.timeout = timeout;
    }

    public boolean isDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public Relay getRelay() {
        return relay;
    }

    public Webhook getWebhook() {
        return webhook;
    }

    public Login getLogin() {
        return login;
    }

    public Mcp getMcp() {
        return mcp;
    }

    /** The relay routes {@code @touchque/web} calls; on when a {@code RelayOptions<HttpServletRequest>} bean exists. */
    public static class Relay {
        /** Where the relay is mounted. */
        private String path = "/touchque";

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }
    }

    /** The verified webhook endpoint; on when a {@link TouchQueWebhookListener} bean exists. */
    public static class Webhook {
        private String path = "/webhooks/touchque";
        /** How old a delivery may be. */
        private Duration tolerance = Duration.ofSeconds(300);

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public Duration getTolerance() {
            return tolerance;
        }

        public void setTolerance(Duration tolerance) {
            this.tolerance = tolerance;
        }
    }

    /**
     * TouchQue Login through Spring Security: sign-in with {@code domain} + {@code client-id}
     * (OAuth2 login with PKCE), and your API's access tokens with {@code domain} + {@code audience}
     * (resource server).
     */
    public static class Login {
        /** Your tenant: acme.login.touchque.com or your own domain. */
        private String domain;
        private String clientId;
        /** Confidential apps (server side); without it the app is public. */
        private String clientSecret;
        private List<String> scope = new ArrayList<>(List.of("openid", "profile", "email"));
        /** Your API's identifier: the access tokens' aud (turns on the resource server decoder). */
        private String audience;
        /** The Spring Security registration id (the sign-in starts at /oauth2/authorization/{id}). */
        private String registrationId = "touchque";
        /** Where to go after signing out (must be a registered sign-out URL); {baseUrl} works. */
        private String postLogoutRedirectUri = "{baseUrl}";

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public List<String> getScope() {
            return scope;
        }

        public void setScope(List<String> scope) {
            this.scope = scope;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getRegistrationId() {
            return registrationId;
        }

        public void setRegistrationId(String registrationId) {
            this.registrationId = registrationId;
        }

        public String getPostLogoutRedirectUri() {
            return postLogoutRedirectUri;
        }

        public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
            this.postLogoutRedirectUri = postLogoutRedirectUri;
        }
    }

    /** An MCP server whose authorization server is TouchQue SSO; on when {@code issuer} and {@code resource} are set. */
    public static class Mcp {
        /** TouchQue SSO's MCP issuer, e.g. https://sso.touchque.com/mcp. */
        private String issuer;
        /** This MCP server's URL (the audience of its tokens). */
        private String resource;
        private String resourceName;
        /** Tool name → the scope it needs. */
        private Map<String, String> tools = new LinkedHashMap<>();
        /** Paths whose requests need a TouchQue token (default: the path of {@code resource}). */
        private List<String> paths = new ArrayList<>();

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getResource() {
            return resource;
        }

        public void setResource(String resource) {
            this.resource = resource;
        }

        public String getResourceName() {
            return resourceName;
        }

        public void setResourceName(String resourceName) {
            this.resourceName = resourceName;
        }

        public Map<String, String> getTools() {
            return tools;
        }

        public void setTools(Map<String, String> tools) {
            this.tools = tools;
        }

        public List<String> getPaths() {
            return paths;
        }

        public void setPaths(List<String> paths) {
            this.paths = paths;
        }
    }
}
