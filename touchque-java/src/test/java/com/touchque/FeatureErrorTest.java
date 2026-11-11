package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A feature the workspace's organization cannot use comes back as a typed exception
 * with the feature's id, still a TouchqueApiException. Same scenarios as the Node SDK,
 * against the shared fake Touchque API.
 */
class FeatureErrorTest {
    private final Support.FakeApi api = Support.FakeApi.get();

    @BeforeEach
    void setUp() {
        api.reset();
        api.link("jane@acme.com");
    }

    @AfterEach
    void tearDown() {
        Map<String, Object> off = new HashMap<>();
        off.put("featureRefused", null);
        api.opts(off);
    }

    @Test
    void eachFeatureRefusalHasItsOwnException() {
        Object[][] cases = {
            {"feature_not_in_plan", TouchqueFeatureNotInPlanException.class, TouchqueFeatureException.Reason.NOT_IN_PLAN},
            {"feature_read_only", TouchqueFeatureReadOnlyException.class, TouchqueFeatureException.Reason.READ_ONLY},
            {"feature_off", TouchqueFeatureOffException.class, TouchqueFeatureException.Reason.OFF},
        };
        for (Object[] c : cases) {
            api.opts(Map.of("featureRefused", c[0], "feature", "device_risk"));
            TouchqueFeatureException e = assertThrows(TouchqueFeatureException.class, () -> api.client().login().request("jane@acme.com"));
            assertInstanceOf((Class<?>) c[1], e);
            assertInstanceOf(TouchqueApiException.class, e);
            assertEquals(403, e.status());
            assertEquals("device_risk", e.feature());
            assertEquals(c[2], e.featureReason());
        }
    }

    @Test
    void otherRefusalsStayPlainApiExceptions() {
        api.opts(Map.of("blocked", "access_policy"));
        TouchqueApiException e = assertThrows(TouchqueApiException.class, () -> api.client().login().request("jane@acme.com"));
        assertFalse(e instanceof TouchqueFeatureException);
    }
}
