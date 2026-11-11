package example.login;

import java.security.Principal;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** An app that only signs in with Touchque Login (no security chain of its own, no API key). */
@SpringBootApplication
public class LoginApp {
    @RestController
    static class Pages {
        @GetMapping("/me")
        public String me(Principal principal) {
            return principal.getName();
        }
    }
}
