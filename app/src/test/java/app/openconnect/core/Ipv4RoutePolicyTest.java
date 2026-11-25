package app.openconnect.core;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class Ipv4RoutePolicyTest {
    private static final String ENDPOINT = "208.98.222.239";

    @Test
    public void globalVpnAllowsAnEndpointOutsideLanExclusions() {
        assertTrue(Ipv4RoutePolicy.allows(ENDPOINT, Collections.emptyList(),
                Arrays.asList("192.168.0.0/255.255.0.0", "fe80::/10")));
    }

    @Test
    public void respectsIpv4InclusionsAndExclusions() {
        assertFalse(Ipv4RoutePolicy.allows(ENDPOINT, Arrays.asList("10.0.0.0/8"), null));
        assertFalse(Ipv4RoutePolicy.allows(ENDPOINT, Arrays.asList("0.0.0.0/0"),
                Arrays.asList("208.98.222.0/24")));
        assertTrue(Ipv4RoutePolicy.allows(ENDPOINT, Arrays.asList("208.98.0.0/16"), null));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsMalformedServerExclusion() {
        Ipv4RoutePolicy.allows(ENDPOINT, null, Arrays.asList("208.98.222.0/255.0.255.0"));
    }
}
