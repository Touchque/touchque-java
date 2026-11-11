package example.app;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.touchque.LoginDetail;
import com.touchque.spring.RequireTouchque;
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
                .details(c -> List.of(LoginDetail.of("Amount", c.argument(Transfer.class).amount())));
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
