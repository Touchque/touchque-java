package example.nokeys;

import com.touchque.spring.RequireTouchque;
import com.touchque.spring.TouchqueGuardOptions;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** An app with a guarded method and no Touchque API key or secret. */
@SpringBootApplication
public class NoKeysApp {
    /** How often the guarded method ran. */
    public static final AtomicInteger RUNS = new AtomicInteger();

    @RestController
    static class Payments {
        @PostMapping("/pay")
        @RequireTouchque("SEND_MONEY")
        public Map<String, Object> pay() {
            RUNS.incrementAndGet();
            return Map.of("ok", true);
        }
    }

    @Bean
    TouchqueGuardOptions sendMoney() {
        return TouchqueGuardOptions.forAction("SEND_MONEY").user(c -> c.request().getHeader("X-Test-User"));
    }

    @Bean
    SecurityFilterChain open(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a.anyRequest().permitAll()).csrf(c -> c.disable());
        return http.build();
    }
}
