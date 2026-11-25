package app.openconnect.core;

import java.util.List;

final class Ipv4RoutePolicy {
    private Ipv4RoutePolicy() {}

    static boolean allows(String address, List<String> includes, List<String> excludes) {
        long target = ipv4(address);
        boolean hasIpv4Include = false;
        boolean included = false;
        if (includes != null) {
            for (String route : includes) {
                if (route.contains(":")) continue;
                hasIpv4Include = true;
                included |= contains(route, target);
            }
        }
        if (hasIpv4Include && !included) return false;
        if (excludes != null) {
            for (String route : excludes) {
                if (!route.contains(":") && contains(route, target)) return false;
            }
        }
        return true;
    }

    private static boolean contains(String route, long address) {
        String[] parts = route.trim().split("/", -1);
        if (parts.length > 2) throw new IllegalArgumentException("Invalid IPv4 route");
        long mask = 0xffffffffL;
        if (parts.length == 2) {
            if (parts[1].contains(".")) {
                mask = ipv4(parts[1]);
                long inverse = (mask ^ 0xffffffffL);
                if ((inverse & (inverse + 1)) != 0) throw new IllegalArgumentException("Invalid mask");
            } else {
                int prefix = Integer.parseInt(parts[1]);
                if (prefix < 0 || prefix > 32) throw new IllegalArgumentException("Invalid prefix");
                mask = (mask << (32 - prefix)) & 0xffffffffL;
            }
        }
        return (ipv4(parts[0]) & mask) == (address & mask);
    }

    private static long ipv4(String text) {
        String[] octets = text.split("\\.", -1);
        if (octets.length != 4) throw new IllegalArgumentException("Invalid IPv4 address");
        long address = 0;
        for (String octet : octets) {
            if (!octet.matches("[0-9]{1,3}")) throw new IllegalArgumentException("Invalid IPv4 octet");
            int value = Integer.parseInt(octet);
            if (value > 255) throw new IllegalArgumentException("Invalid IPv4 octet");
            address = (address << 8) | value;
        }
        return address;
    }
}
