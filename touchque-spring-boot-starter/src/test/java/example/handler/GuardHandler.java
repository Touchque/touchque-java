package example.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.touchque.TouchqueClient;
import com.touchque.flow.Guard;
import com.touchque.spring.TouchqueErrorBody;
import com.touchque.spring.TouchqueSpring;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * "Guard inside your handler" as the README shows it: the client bean looked up per request
 * (Guard.withoutClient while it cannot be built) and the answer from Guard.response. The user comes
 * from X-Test-User; {@code errorBody=true} shapes refusals with the app's TouchqueErrorBody bean.
 */
@RestController
public class GuardHandler {
    private final ObjectProvider<TouchqueClient> touchque;
    private final ObjectProvider<TouchqueErrorBody> errorBodies;
    private final ObjectMapper mapper;

    public GuardHandler(ObjectProvider<TouchqueClient> touchque, ObjectProvider<TouchqueErrorBody> errorBodies, ObjectMapper mapper) {
        this.touchque = touchque;
        this.errorBodies = errorBodies;
        this.mapper = mapper;
    }

    @PostMapping("/handler/{action}")
    public ResponseEntity<?> guarded(@PathVariable("action") String action, @RequestParam(name = "errorBody", defaultValue = "false") boolean errorBody,
            HttpServletRequest request) {
        Guard.Input input = new Guard.Input(request.getHeader("X-Test-User"), action)
                .headers(request::getHeader)
                .ip(TouchqueSpring.clientIp(request))
                .userAgent(request.getHeader("User-Agent"));
        Guard.Result r;
        try {
            r = Guard.run(touchque.getObject(), input);
        } catch (BeansException noKeys) {
            r = Guard.withoutClient(input);
        }
        if (r.approved() == null) {
            Guard.Response res = errorBody ? Guard.response(r, errorBodies.getIfUnique(), mapper, null) : Guard.response(r, null);
            return ResponseEntity.status(res.status()).headers(h -> res.headers().forEach(h::set)).body(res.body());
        }
        return ResponseEntity.ok(Map.of("ok", true, "via", r.approved().confirmedVia()));
    }
}
