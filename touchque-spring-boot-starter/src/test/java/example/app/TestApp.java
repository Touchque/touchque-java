package example.app;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.LoginDetail;
import com.touchque.spring.RequireTouchque;
import com.touchque.spring.TouchqueErrorBody;
import com.touchque.spring.TouchqueGuardOptions;
import com.touchque.spring.TouchqueSpring;
import com.touchque.spring.TouchqueWebhookListener;
import com.touchque.agents.McpAuth;
import com.touchque.flow.Approval;
import com.touchque.relay.RelayOptions;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** A small app using every piece of the starter. */
@SpringBootApplication
public class TestApp {
    public static final List<ObjectNode> EVENTS = new CopyOnWriteArrayList<>();
    /** The webhook listener throws once (the database is down) when set. */
    public static final AtomicBoolean FAIL_NEXT_EVENT = new AtomicBoolean();
    /** How often the TouchqueErrorBody bean ran; it throws a checked IOException while ERROR_BODY_THROWS is set. */
    public static final AtomicInteger ERROR_BODIES = new AtomicInteger();
    public static final AtomicBoolean ERROR_BODY_THROWS = new AtomicBoolean();
    /** When set, the TouchqueErrorBody bean returns it (something its ObjectMapper cannot write, say). */
    public static final AtomicReference<Object> ERROR_BODY_RESULT = new AtomicReference<>();

    public record Transfer(String amount) {
    }

    @RestController
    static class Payments {
        @PostMapping("/transfer")
        @RequireTouchque("SEND_MONEY")
        public Map<String, Object> transfer(@RequestBody Transfer t, Approval approval) {
            return Map.of("ok", true, "amount", t.amount(), "via", approval.assurance().method());
        }
    }

    @RestController
    static class Account {
        @PostMapping("/account")
        @RequireTouchque("LOGIN")
        public Map<String, Object> account(Approval approval) {
            return Map.of("ok", true, "via", approval.confirmedVia());
        }
    }

    @RestController
    static class Mcp {
        private final McpAuth auth;

        Mcp(McpAuth auth) {
            this.auth = auth;
        }

        @PostMapping("/mcp")
        public Map<String, Object> call(HttpServletRequest request, @RequestBody Map<String, String> body) {
            McpAuth.Claims claims = TouchqueSpring.mcpClaims(request);
            auth.requireTool(claims, body.get("tool"));
            return Map.of("sub", claims.sub(), "tool", body.get("tool"));
        }
    }

    @Bean
    TouchqueGuardOptions sendMoney() {
        return TouchqueGuardOptions.forAction("SEND_MONEY")
                .user(c -> "jane@acme.com")
                .details(c -> List.of(LoginDetail.of("Amount", c.argument(Transfer.class).amount())))
                .errorBody(r -> "refused: " + r.code());
    }

    @Bean
    TouchqueGuardOptions login() {
        return TouchqueGuardOptions.forAction("LOGIN").user(c -> c.request().getHeader("X-Test-User"));
    }

    /** The app's own error shape for every guarded method without one of its own. */
    @Bean
    TouchqueErrorBody errorBody() {
        return r -> {
            ERROR_BODIES.incrementAndGet();
            if (ERROR_BODY_THROWS.get()) sneakyThrow(new java.io.IOException("the error template is broken"));
            Object result = ERROR_BODY_RESULT.get();
            return result != null ? result : Map.of("message", r.message(), "code", r.code());
        };
    }

    /** Throws a checked exception from a lambda, as Kotlin or @SneakyThrows code can. */
    @SuppressWarnings("unchecked")
    static <E extends Exception> void sneakyThrow(Exception e) throws E {
        throw (E) e;
    }

    @Bean
    RelayOptions<HttpServletRequest> relayOptions() {
        return new RelayOptions<HttpServletRequest>(req -> null)
                .getLoginUser(req -> req.getHeader("X-Test-User"))
                .onAuthenticated((req, res, info) -> res.setHeader("X-Signed-In", info.externalUsername()));
    }

    @Bean
    TouchqueWebhookListener webhooks() {
        return (event, request) -> {
            if (FAIL_NEXT_EVENT.getAndSet(false)) throw new IllegalStateException("the database is down");
            EVENTS.add(event);
        };
    }

    @Bean
    @Profile("open")
    SecurityFilterChain open(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a.anyRequest().permitAll()).csrf(c -> c.disable());
        return http.build();
    }
}
