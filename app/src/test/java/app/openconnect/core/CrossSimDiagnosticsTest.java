package app.openconnect.core;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.StringReader;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class CrossSimDiagnosticsTest {
    @Test
    public void readsCurrentTransportBySlotWithoutUsingHistoricalEvents() throws Exception {
        String dump = "  AccessNetworksManager-0:\n    preferred transports=\n"
                + "      default: WWAN\n      ims: WWAN\n    Local logs=\n"
                + "      setPreferredTransports: apnType=ims, transport=WLAN\n"
                + "  AccessNetworksManager-1:\n    preferred transports=\n"
                + "      ims: WLAN\n    Local logs=\n";
        assertEquals(Map.of(0, "WWAN", 1, "WLAN"), CrossSimDiagnostics
                .parsePreferredImsTransports(new BufferedReader(new StringReader(dump))));
    }
    @Test
    public void distinguishesIwlanAndCrossSimRegistration() {
        assertEquals("LTE", CrossSimDiagnostics.technology(true, 0));
        assertEquals("IWLAN", CrossSimDiagnostics.technology(true, 1));
        assertEquals("CROSS_SIM", CrossSimDiagnostics.technology(true, 2));
    }

    @Test
    public void technologyAloneDoesNotEstablishRegistration() {
        assertEquals("Unregistered", CrossSimDiagnostics.technology(false, 2));
        assertEquals("Unknown", CrossSimDiagnostics.technology(null, 2));
        assertEquals("Unknown", CrossSimDiagnostics.technology(true, -1));
        assertEquals("Unknown", CrossSimDiagnostics.technology(true, 100));
    }
}
