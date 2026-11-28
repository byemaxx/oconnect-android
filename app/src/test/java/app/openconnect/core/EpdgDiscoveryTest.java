package app.openconnect.core;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;
import static org.junit.Assert.*;

public class EpdgDiscoveryTest {
    @Test public void homePlmnPadsTwoDigitMnc() {
        assertEquals("epdg.epc.mnc001.mcc460.pub.3gppnetwork.org", EpdgDiscovery.hostname("46001"));
        assertEquals("epdg.epc.mnc490.mcc302.pub.3gppnetwork.org", EpdgDiscovery.hostname("302490"));
    }
    @Test(expected = IllegalArgumentException.class) public void rejectsInvalidPlmn() {
        EpdgDiscovery.hostname("302");
    }
    @Test public void validatesHostnames() {
        assertTrue(EpdgDiscovery.validHost("epdg.example.test"));
        assertFalse(EpdgDiscovery.validHost("epdg.example.test;id"));
        assertFalse(EpdgDiscovery.validHost("bad..example"));
    }

    @Test public void autoKeepsLoneKnownSimWithoutWifiCallingPreference() throws IOException {
        EpdgDiscovery.Subscription sim = new EpdgDiscovery.Subscription(4, 0, "302490", null);
        assertSame(sim, EpdgDiscovery.select(Collections.singletonList(sim), "auto"));
        sim = new EpdgDiscovery.Subscription(4, 0, "302490", false);
        assertSame(sim, EpdgDiscovery.select(Collections.singletonList(sim), "auto"));
    }

    @Test public void autoRejectsUnreadableCompetingSim() {
        EpdgDiscovery.Subscription eligible = new EpdgDiscovery.Subscription(4, 0, "302490", true);
        for (EpdgDiscovery.Subscription other : Arrays.asList(
                new EpdgDiscovery.Subscription(5, null, null, null),
                new EpdgDiscovery.Subscription(5, -1, null, true),
                new EpdgDiscovery.Subscription(5, 1, "", true),
                new EpdgDiscovery.Subscription(5, 1, "46001", null))) {
            IOException failure = assertThrows(IOException.class,
                    () -> EpdgDiscovery.select(Arrays.asList(eligible, other), "auto"));
            assertTrue(failure.getMessage().contains("Multiple eligible or unknown SIMs"));
        }
    }

    @Test public void autoChoosesUniqueEligibleSimWithKnownDetails() throws IOException {
        EpdgDiscovery.Subscription eligible = new EpdgDiscovery.Subscription(4, 0, "302490", true);
        EpdgDiscovery.Subscription disabled = new EpdgDiscovery.Subscription(5, 1, "46001", false);
        assertSame(eligible, EpdgDiscovery.select(Arrays.asList(disabled, eligible), "auto"));
    }

    @Test public void explicitSlotUsesRequestedSimWithWifiCallingDisabled() throws IOException {
        EpdgDiscovery.Subscription eligible = new EpdgDiscovery.Subscription(4, 0, "302490", true);
        EpdgDiscovery.Subscription requested = new EpdgDiscovery.Subscription(5, 1, "46001", false);
        assertSame(requested, EpdgDiscovery.select(Arrays.asList(eligible, requested), "1"));
    }

    @Test public void explicitSlotDistinguishesInactiveFromUnavailable() {
        EpdgDiscovery.Subscription other = new EpdgDiscovery.Subscription(4, 0, "302490", true);
        IOException inactive = assertThrows(IOException.class,
                () -> EpdgDiscovery.select(Collections.singletonList(other), "1"));
        assertTrue(inactive.getMessage().contains("inactive"));

        for (List<EpdgDiscovery.Subscription> active : Arrays.asList(
                null,
                Arrays.asList(other, new EpdgDiscovery.Subscription(5, null, null, false)),
                Arrays.asList(other, new EpdgDiscovery.Subscription(5, 1, null, true)))) {
            IOException unavailable = assertThrows(IOException.class, () -> EpdgDiscovery.select(active, "1"));
            assertTrue(unavailable.getMessage().contains("information unavailable"));
        }
    }
}
