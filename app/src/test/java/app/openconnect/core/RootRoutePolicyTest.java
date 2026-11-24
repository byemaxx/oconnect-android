package app.openconnect.core;

import org.junit.Test;
import java.util.Arrays;
import java.util.Collections;
import static org.junit.Assert.*;

public class RootRoutePolicyTest {
    @Test public void validIpAndNetmask() {
        assertEquals(24, RootRoutePolicy.prefix("255.255.255.0"));
        assertEquals(0, RootRoutePolicy.prefix("0.0.0.0"));
        assertTrue(RootRoutePolicy.contains("198.51.100.0/24", RootRoutePolicy.ipv4("198.51.100.6")));
        assertFalse(RootRoutePolicy.contains("198.51.100.0/24", RootRoutePolicy.ipv4("198.51.101.6")));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsInjection() { RootRoutePolicy.target("8.8.8.8; id"); }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsPrivateTarget() { RootRoutePolicy.target("192.168.1.1"); }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsExcludedAddress() {
        RootRoutePolicy.checkServerRoutes("8.8.8.8", Collections.emptyList(),
                Arrays.asList("8.8.8.0/24"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsRestrictedSplitTunnel() {
        RootRoutePolicy.checkServerRoutes("8.8.8.8", Arrays.asList("10.0.0.0/8"),
                Collections.emptyList());
    }

    @Test public void allowsServerDefaultRoute() {
        RootRoutePolicy.checkServerRoutes("8.8.8.8", Arrays.asList("0.0.0.0/0"),
                Collections.emptyList());
    }
}
