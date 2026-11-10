package com.touchque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.touchque.internal.Json;
import com.touchque.resources.DeviceRisk;
import com.touchque.resources.Risk;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Device risk against the fake API: the report goes through untouched and the answer fails toward asking. */
class DeviceRiskTest {
    private final Support.FakeApi api = Support.FakeApi.get();

    @BeforeEach
    void reset() {
        api.reset();
        api.link("ayse@acme.com");
    }

    @Test
    void theFormFieldAsItCameIsAnsweredNeverThrown() {
        for (String value : new String[] {null, ""}) {
            DeviceRisk.CheckResult r = api.client().deviceRisk().check(DeviceRisk.CheckOptions.ofRequest(value).externalUsername("ayse@acme.com"));
            assertEquals("missing", r.report());
            assertEquals(null, r.visitorId());
            assertEquals(List.of("device_identification_missing"), r.signals().stream().map(DeviceRisk.Signal::code).toList());
            assertFalse(r.stepUp());
            assertTrue(r.wouldStepUp());
        }
        assertEquals("missing", api.client().deviceRisk().check(DeviceRisk.CheckOptions.ofReport("")).report());
        assertEquals("unknown", api.client().deviceRisk().check("nope").report());
    }

    @Test
    void checkSendsTheReportAndReadsTheAnswer() {
        DeviceRisk.CheckResult r = api.client().deviceRisk().check(DeviceRisk.CheckOptions.ofRequest("dre_flaggedaaaaaaaaaaaaaaa").event("sign_up")
                .externalUsername("ayse@acme.com").clientIp("203.0.113.7"));
        assertEquals("ok", r.report());
        assertEquals("tqv_fakeVisitor00000001", r.visitorId());
        assertEquals("DRK-2QX", r.caseCode());
        assertFalse(r.signals().get(0).enforced());
        assertEquals("tqv_fakeVisitor00000001", api.client().deviceRisk().getEvent("dre_aaaaaaaaaaaaaaaaaaaaaa").get("visitorId").asText());
        assertTrue(api.client().deviceRisk().check(DeviceRisk.CheckOptions.ofReport("REPORT")).signals().isEmpty());
        assertEquals(List.of("device_many_accounts"), r.signals().stream().map(DeviceRisk.Signal::code).toList());
        assertFalse(r.stepUp());
        assertTrue(r.wouldStepUp());
        assertEquals("shadow", r.mode());
    }

    @Test
    void badInputFailsBeforeAnyRequest() {
        assertThrows(TouchQueConfigException.class, () -> api.client().deviceRisk().check(DeviceRisk.CheckOptions.ofReport("r").event("tracking")));
        assertThrows(TouchQueConfigException.class, () -> api.client().deviceRisk().getEvent("../users"));
    }

    @Test
    void theAnswerFailsTowardAsking() {
        assertTrue(DeviceRisk.parseCheck(Json.object()).stepUp());
        assertFalse(DeviceRisk.parseCheck(Json.object().put("stepUp", false)).stepUp());
        DeviceRisk.CheckResult r = DeviceRisk.parseCheck(Json.parse("{\"signals\":[{\"code\":\"device_tampered\",\"text\":\"t\"},null,{\"text\":\"x\"}],\"requires\":\"passkey\"}"));
        assertEquals(1, r.signals().size());
        assertEquals("number_match", r.signals().get(0).strength());
        assertEquals("passkey", r.requires());
        assertEquals("invalid", r.report());
    }

    @Test
    void engineUnavailableComesThroughAndANormalAnswerHasNull() {
        DeviceRisk.CheckResult down = DeviceRisk.parseCheck(Json.parse("{\"report\":\"ok\",\"signals\":[],\"stepUp\":true,\"wouldStepUp\":true,\"requires\":\"number_match\",\"mode\":\"enforce\",\"engine\":\"unavailable\"}"));
        assertEquals("unavailable", down.engine());
        assertTrue(down.stepUp());
        assertEquals("number_match", down.requires());
        DeviceRisk.CheckResult normal = DeviceRisk.parseCheck(Json.parse("{\"report\":\"ok\",\"signals\":[],\"stepUp\":false,\"requires\":\"none\",\"mode\":\"shadow\"}"));
        assertNull(normal.engine());
        assertFalse(normal.stepUp());
        assertNull(DeviceRisk.parseCheck(Json.parse("{\"engine\":42}")).engine());
    }

    @Test
    void riskCheckCarriesDeviceRisk() {
        assertTrue(api.client().risk().check(new Risk.CheckOptions("ayse@acme.com").deviceRiskRequestId("dre_aaaaaaaaaaaaaaaaaaaaaa")).prompt());
    }

    @Test
    void theAddressTheCountsAndABotAnswerComeThrough() {
        DeviceRisk.CheckResult r = DeviceRisk.parseCheck(Json.parse("{\"report\":\"ok\",\"network\":{\"type\":\"hosting\"},\"velocity\":{\"identifications1h\":2},\"bot\":{\"result\":\"suspected\"}}"));
        assertEquals("hosting", r.network().get("type").asText());
        assertEquals(2, r.velocity().get("identifications1h").asInt());
        assertEquals("suspected", r.bot().get("result").asText());
        assertNull(DeviceRisk.parseCheck(Json.parse("{\"network\":\"x\"}")).network());
    }

    @Test
    void searchEventsPagesWithTheOpaqueCursorAndSendsTheFilters() {
        DeviceRisk.SearchResult first = api.client().deviceRisk().searchEvents(new DeviceRisk.SearchOptions().account("ada@example.com").stepUp(false).ip("203.0.113.0/24").limit(1));
        assertEquals(List.of("dre_fakeEvent00000000002"), first.events().stream().map(e -> e.get("requestId").asText()).toList());
        assertNull(first.nextCursor());
        assertEquals(Json.parse("{\"account\":\"ada@example.com\",\"stepUp\":\"false\",\"ip\":\"203.0.113.0/24\",\"limit\":\"1\"}"), api.get("/__test/last-device-risk-search"));
        List<String> seen = new java.util.ArrayList<>();
        String cursor = null;
        do {
            DeviceRisk.SearchResult page = api.client().deviceRisk().searchEvents(new DeviceRisk.SearchOptions().limit(1).cursor(cursor));
            page.events().forEach(e -> seen.add(e.get("requestId").asText()));
            cursor = page.nextCursor();
        } while (cursor != null);
        assertEquals(List.of("dre_fakeEvent00000000003", "dre_fakeEvent00000000002", "dre_fakeEvent00000000001"), seen);
        assertThrows(com.touchque.TouchQueConfigException.class, () -> new DeviceRisk.SearchOptions().limit(101));
    }
}
