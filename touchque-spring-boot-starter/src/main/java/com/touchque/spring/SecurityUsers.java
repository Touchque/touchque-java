package com.touchque.spring;

import java.security.Principal;
import org.springframework.security.core.Authentication;
import org.springframework.util.ClassUtils;

/** Reads the email (else sub) from Spring Security principals; loaded only when Spring Security is present. */
final class SecurityUsers {
    private static final ClassLoader LOADER = SecurityUsers.class.getClassLoader();
    private static final boolean OAUTH2 = ClassUtils.isPresent("org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal", LOADER);
    private static final boolean JOSE = ClassUtils.isPresent("org.springframework.security.oauth2.jwt.Jwt", LOADER);

    private SecurityUsers() {
    }

    static String of(Principal p) {
        if (!(p instanceof Authentication a) || !a.isAuthenticated()) return null;
        Object principal = a.getPrincipal();
        String u = OAUTH2 ? OAuth2.of(principal) : null;
        if (u == null && JOSE) u = Jose.of(principal);
        return u;
    }

    private static String first(Object a, Object b) {
        if (a instanceof String s && !s.isEmpty()) return s;
        return b instanceof String s && !s.isEmpty() ? s : null;
    }

    private static final class OAuth2 {
        static String of(Object principal) {
            if (principal instanceof org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal o) {
                return first(o.getAttribute("email"), o.getAttribute("sub"));
            }
            return null;
        }
    }

    private static final class Jose {
        static String of(Object principal) {
            if (principal instanceof org.springframework.security.oauth2.jwt.Jwt j) return first(j.getClaimAsString("email"), j.getSubject());
            return null;
        }
    }
}
