package example.custom;

import com.touchque.TouchqueClient;
import com.touchque.TouchqueOptions;
import com.touchque.spring.RequireTouchque;
import com.touchque.spring.TouchqueErrorBody;
import com.touchque.spring.TouchqueGuardOptions;
import com.touchque.spring.TouchqueProperties;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** An app with its own TouchqueClient bean, a new one per lookup (like a per-tenant client), and two TouchqueErrorBody beans. */
@SpringBootApplication
public class CustomBeansApp {
    /** How many clients the bean method built. */
    public static final AtomicInteger CLIENTS = new AtomicInteger();

    @RestController
    static class Payments {
        @PostMapping("/pay")
        @RequireTouchque("SEND_MONEY")
        public Map<String, Object> pay() {
            return Map.of("ok", true);
        }
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    TouchqueClient tenantClient(TouchqueProperties properties) {
        CLIENTS.incrementAndGet();
        return new TouchqueClient(new TouchqueOptions().apiKey(properties.getApiKey()).apiSecret(properties.getApiSecret()).baseUrl(properties.getBaseUrl()));
    }

    @Bean
    TouchqueGuardOptions sendMoney() {
        return TouchqueGuardOptions.forAction("SEND_MONEY").user(c -> c.request().getHeader("X-Test-User"));
    }

    @Bean
    TouchqueErrorBody oneShape() {
        return r -> Map.of("one", r.code());
    }

    @Bean
    TouchqueErrorBody otherShape() {
        return r -> Map.of("other", r.code());
    }

    @Bean
    SecurityFilterChain open(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a.anyRequest().permitAll()).csrf(c -> c.disable());
        return http.build();
    }
}
