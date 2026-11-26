package app.openconnect.core;

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
}
