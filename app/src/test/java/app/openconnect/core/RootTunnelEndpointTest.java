package app.openconnect.core;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class RootTunnelEndpointTest {
    private final List<RootTunnel.Endpoint> endpoints = Arrays.asList(
            new RootTunnel.Endpoint("carrier.example.test", Collections.singleton("192.0.2.1"), "carrier config"),
            new RootTunnel.Endpoint("home.example.test", Collections.singleton("198.51.100.1"), "home PLMN"));

    @Test public void triesNextHostnameWhenFirstAddressesAreExcluded() {
        RootTunnel.Endpoint selected = RootTunnel.selectEndpoint(endpoints, null,
                Collections.singletonList("192.0.2.0/24"));
        assertEquals("home.example.test", selected.hostname);
        assertEquals(Collections.singleton("198.51.100.1"), selected.addresses);
    }

    @Test public void preservesPriorityWhenBothHostnamesAreAllowed() {
        assertEquals("carrier.example.test", RootTunnel.selectEndpoint(endpoints, null, null).hostname);
    }

    @Test public void returnsNoEndpointWhenNeitherHostnameIsAllowed() {
        assertNull(RootTunnel.selectEndpoint(endpoints, Collections.singletonList("203.0.113.0/24"), null));
    }
}
