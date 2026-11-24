/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package app.openconnect.core;

import java.util.List;

/** Numeric IPv4 only. Never resolves a hostname or expands the server's routes. */
final class RootRoutePolicy {
    private RootRoutePolicy() {}

    static long ipv4(String value) {
        if (value == null || !value.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) {
            throw new IllegalArgumentException("Enter a numeric IPv4 address");
        }
        long result = 0;
        for (String part : value.split("\\.")) {
            int octet = Integer.parseInt(part);
            if (octet > 255 || (part.length() > 1 && part.charAt(0) == '0')) {
                throw new IllegalArgumentException("Invalid IPv4 address");
            }
            result = (result << 8) | octet;
        }
        return result;
    }

    static int prefix(String value) {
        if (value == null) throw new IllegalArgumentException("Missing netmask");
        if (value.matches("[0-9]{1,2}")) {
            int n = Integer.parseInt(value);
            if (n <= 32) return n;
        } else {
            long m = ipv4(value);
            int n = Long.bitCount(m);
            if (m == mask(n)) return n;
        }
        throw new IllegalArgumentException("Invalid IPv4 netmask");
    }

    private static long mask(int n) {
        return n == 0 ? 0 : (0xffffffffL << (32 - n)) & 0xffffffffL;
    }

    static boolean contains(String cidr, long address) {
        String[] parts = cidr.trim().split("/", -1);
        if (parts.length > 2) throw new IllegalArgumentException("Invalid route");
        long network = ipv4(parts[0]);
        long mask = mask(parts.length == 2 ? prefix(parts[1]) : 32);
        return (network & mask) == (address & mask);
    }

    static String target(String text) {
        String s = text == null ? "" : text.trim();
        long a = ipv4(s);
        int first = (int)(a >>> 24);
        int second = (int)((a >>> 16) & 255);
        if (first == 0 || first == 10 || first == 127 || first >= 224
                || (first == 169 && second == 254)
                || (first == 172 && second >= 16 && second <= 31)
                || (first == 192 && second == 168)
                || (first == 100 && second >= 64 && second <= 127)) {
            throw new IllegalArgumentException("Enter the public IPv4 address of the ePDG");
        }
        return s;
    }

    static void checkServerRoutes(String target, List<String> includes, List<String> excludes) {
        long a = ipv4(target);
        boolean hasIpv4Include = false, included = false;
        for (String route : includes) {
            if (route.contains(":")) continue;
            hasIpv4Include = true;
            if (contains(route, a)) included = true;
        }
        if (hasIpv4Include && !included) {
            throw new IllegalArgumentException("ePDG is outside the VPN server's permitted IPv4 routes");
        }
        for (String route : excludes) {
            if (!route.contains(":") && contains(route, a)) {
                throw new IllegalArgumentException("ePDG is excluded by the VPN server");
            }
        }
    }
}
