/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package app.openconnect.core;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.system.Os;
import android.util.Log;

import org.infradead.libopenconnect.LibOpenConnect;

import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Experimental, opt-in IPv4 IKE/NAT-T routing without establishing an Android VPN.
 * The privileged helper creates a non-persistent TUN and passes its descriptor
 * over an authenticated Unix socket. The SSL/MFA session remains in this app.
 */
final class RootTunnel implements AutoCloseable {
    static final String ENABLED = "root_epdg_enabled";
    static final String TARGETS = "root_epdg_targets";
    static final String DEFAULT_TARGET = "epdg.epc.mnc490.mcc302.pub.3gppnetwork.org";
    private static final String TAG = "OConnectRoot";
    private static final int MAX_TARGETS = 8;
    private LocalSocket control;
    private ParcelFileDescriptor tun;
    private java.lang.Process helper;

    private static Uplink activeUplink;

    private static boolean isWifi(NetworkCapabilities caps) {
        return caps != null
                && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }

    /**
     * Select physical Wi-Fi before authenticating. Binding is app-process scoped,
     * not system-wide, and is restored when the session exits.
     */
    static final class Uplink implements AutoCloseable {
        private final ConnectivityManager cm;
        private final Network network;
        private final Network previous;
        final Set<String> targets;
        final String interfaceName;
        final boolean freedomRelay;

        private Uplink(ConnectivityManager cm, Network network, Network previous,
                Set<String> targets, String interfaceName, boolean freedomRelay) {
            this.cm = cm;
            this.network = network;
            this.previous = previous;
            this.targets = targets;
            this.interfaceName = interfaceName;
            this.freedomRelay = freedomRelay;
        }

        void verifyAvailable() throws IOException {
            if (!isWifi(cm.getNetworkCapabilities(network))) {
                throw new IOException("Selected Wi-Fi connection was lost during VPN setup");
            }
            if (!network.equals(cm.getBoundNetworkForProcess())) {
                throw new IOException("Wi-Fi process binding changed during VPN setup");
            }
        }

        @Override
        public void close() {
            synchronized (RootTunnel.class) {
                if (activeUplink != this) return;
                try {
                    if (network.equals(cm.getBoundNetworkForProcess())
                            && !cm.bindProcessToNetwork(previous)) {
                        // A previously bound network may have disappeared.
                        cm.bindProcessToNetwork(null);
                    }
                } catch (RuntimeException e) {
                    Log.w(TAG, "Unable to restore previous app network binding", e);
                } finally {
                    activeUplink = null;
                }
            }
        }
    }

    static synchronized Uplink prepareUplink(Context context, String targets)
            throws IOException {
        if (Build.VERSION.SDK_INT < 26) {
            throw new IOException("Root ePDG mode requires Android 8 or newer");
        }
        if (activeUplink != null) {
            throw new IOException("Previous root session is still closing; disconnect first");
        }
        ConnectivityManager cm = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) throw new IOException("Connectivity service unavailable");

        Network active = cm.getActiveNetwork();
        NetworkCapabilities activeCaps = active == null ? null : cm.getNetworkCapabilities(active);
        if (activeCaps != null && activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            throw new IOException("Another Android VPN is active. Disconnect it before starting Root ePDG mode.");
        }

        Network wifi = isWifi(activeCaps) ? active : null;
        if (wifi == null) {
            // A connected Wi-Fi network may not be Android's default network,
            // especially with dual SIM or an unvalidated Wi-Fi connection.
            for (Network candidate : cm.getAllNetworks()) {
                NetworkCapabilities caps = cm.getNetworkCapabilities(candidate);
                if (!isWifi(caps)) continue;
                if (wifi == null) wifi = candidate;
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    wifi = candidate;
                    break;
                }
            }
        }
        if (wifi == null) {
            throw new IOException("No connected Wi-Fi internet network found. Connect to Wi-Fi before starting Root ePDG mode.");
        }
        LinkProperties links = cm.getLinkProperties(wifi);
        if (links == null || links.getInterfaceName() == null) {
            throw new IOException("Wi-Fi link is not ready yet. Try reconnecting to Wi-Fi.");
        }

        String input = targets.trim();
        boolean freedomRelay = input.toLowerCase(Locale.ROOT).startsWith("freedom=");
        Set<String> resolved = freedomRelay
                ? Collections.singleton(freedomEndpoint(input.substring("freedom=".length())))
                : resolveTargets(wifi, targets);
        Network previous = cm.getBoundNetworkForProcess();
        if (!cm.bindProcessToNetwork(wifi)) {
            throw new IOException("Could not bind OConnect to the selected Wi-Fi network");
        }
        Uplink uplink = new Uplink(cm, wifi, previous, resolved, links.getInterfaceName(), freedomRelay);
        activeUplink = uplink;
        Log.i(TAG, "Selected physical Wi-Fi: " + uplink.interfaceName
                + "; default network was " + active + "; targets=" + resolved);
        return uplink;
    }

    private static String freedomEndpoint(String input) throws IOException {
        String value = input.trim();
        if (!value.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) {
            throw new IOException("Freedom relay requires freedom=<public IPv4 address>");
        }
        InetAddress address = InetAddress.getByName(value);
        if (!(address instanceof Inet4Address) || address.isAnyLocalAddress()
                || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isMulticastAddress() || address.isSiteLocalAddress()) {
            throw new IOException("Freedom relay requires a public IPv4 address");
        }
        return address.getHostAddress();
    }

    private static Set<String> resolveTargets(Network wifi, String targets) throws IOException {
        Set<String> resolved = new LinkedHashSet<>();
        for (String host : targets.trim().split("[,\\s]+")) {
            if (host.isEmpty()) continue;
            if (!host.matches("[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}")) {
                throw new IOException("Invalid ePDG address or hostname");
            }
            InetAddress[] addresses;
            try {
                addresses = wifi.getAllByName(host);
            } catch (IOException e) {
                throw new IOException("Cannot resolve ePDG on Wi-Fi: " + host
                        + ". Check DNS or configure known-good IPv4 addresses.", e);
            }
            for (InetAddress addr : addresses) {
                if (addr instanceof Inet4Address && !addr.isAnyLocalAddress()
                        && !addr.isLoopbackAddress() && !addr.isLinkLocalAddress()
                        && !addr.isMulticastAddress() && !addr.isSiteLocalAddress()) {
                    resolved.add(addr.getHostAddress());
                }
            }
        }
        if (resolved.isEmpty() || resolved.size() > MAX_TARGETS) {
            throw new IOException("Specify 1-8 public IPv4 ePDG addresses");
        }
        return resolved;
    }

    static RootTunnel open(Context context, LibOpenConnect.IPInfo ip, Uplink uplink)
            throws Exception {
        // Do not re-evaluate the default network after CSTP authentication.
        // The preflight-selected physical Wi-Fi must still be usable.
        uplink.verifyAvailable();
        if (ip.addr == null || ip.netmask == null) {
            throw new IOException("VPN server did not assign an IPv4 address");
        }
        // Do not replace server-selected split routes with an unrestricted tunnel.
        if (ip.splitIncludes != null && !ip.splitIncludes.isEmpty()) {
            throw new IOException("Root ePDG mode currently requires a full IPv4 VPN");
        }
        InetAddress vpnAddress = InetAddress.getByName(ip.addr);
        if (!(vpnAddress instanceof Inet4Address)) {
            throw new IOException("Invalid VPN IPv4 address");
        }
        CIDRIP cidr = new CIDRIP(ip.addr, ip.netmask);
        Set<String> resolved = uplink.targets;
        int mtu = ip.MTU > 0 ? ip.MTU : 1400;
        if (mtu < 576 || mtu > 9000) throw new IOException("Invalid tunnel MTU");
        String nonce = UUID.randomUUID().toString().replace("-", "");
        String socketName = "oconnect-root-" + nonce;
        String executable = RootAccess.helperPath(context);
        ArrayList<String> args = new ArrayList<>();
        args.add(executable);
        args.add(socketName);
        args.add(Integer.toString(android.os.Process.myUid()));
        args.add(vpnAddress.getHostAddress() + "/" + cidr.len);
        args.add(Integer.toString(mtu));
        if (uplink.freedomRelay) {
            LinkProperties links = uplink.cm.getLinkProperties(uplink.network);
            if (links == null || !uplink.interfaceName.equals(links.getInterfaceName())) {
                throw new IOException("Wi-Fi link changed before Freedom relay setup");
            }
            String wifiAddress = null;
            for (LinkAddress address : links.getLinkAddresses()) {
                if (address.getAddress() instanceof Inet4Address) {
                    wifiAddress = address.getAddress().getHostAddress();
                    break;
                }
            }
            if (wifiAddress == null) throw new IOException("Freedom relay requires Wi-Fi IPv4");
            String dns4 = "-", dns6 = "-";
            for (InetAddress dns : links.getDnsServers()) {
                if (dns instanceof Inet4Address && dns4.equals("-")) {
                    dns4 = dns.getHostAddress();
                } else if (dns instanceof Inet6Address && dns.isLinkLocalAddress() && dns6.equals("-")) {
                    dns6 = dns.getHostAddress().split("%", 2)[0];
                }
            }
            if (dns4.equals("-") && dns6.equals("-")) {
                throw new IOException("Freedom relay requires Wi-Fi IPv4 or link-local IPv6 DNS");
            }
            Collections.addAll(args, "--freedom-relay", uplink.interfaceName, wifiAddress, dns4, dns6);
        }
        args.addAll(resolved);
        RootTunnel result = new RootTunnel();
        boolean success = false;
        try {
            result.helper = RootAccess.start(args.toArray(new String[0]));
            final java.lang.Process proc = result.helper;
            Thread logger = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(proc.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) Log.i(TAG, line);
                } catch (IOException e) {
                    Log.d(TAG, "Helper output closed", e);
                }
            }, "RootTunLog");
            logger.setDaemon(true);
            logger.start();

            long deadline = SystemClock.elapsedRealtime() + 60000;
            while (true) {
                LocalSocket candidate = new LocalSocket();
                try {
                    candidate.connect(new LocalSocketAddress(socketName,
                            LocalSocketAddress.Namespace.ABSTRACT));
                    result.control = candidate;
                    break;
                } catch (IOException e) {
                    candidate.close();
                    if (!proc.isAlive() || SystemClock.elapsedRealtime() >= deadline) {
                        throw new IOException("Root helper did not start; check KernelSU and logcat", e);
                    }
                    SystemClock.sleep(200);
                }
            }
            if (result.control.getPeerCredentials().getUid() != 0) {
                throw new IOException("Root helper peer UID is not zero");
            }
            result.control.setSoTimeout(60000);
            if (result.control.getInputStream().read() != 1) {
                throw new IOException("Root helper failed to configure tunnel; check logcat");
            }
            FileDescriptor[] descriptors = result.control.getAncillaryFileDescriptors();
            if (descriptors == null || descriptors.length != 1) {
                if (descriptors != null) {
                    for (FileDescriptor fd : descriptors) {
                        try { Os.close(fd); } catch (Exception ignored) {}
                    }
                }
                throw new IOException("Root helper did not return a TUN descriptor");
            }
            try {
                result.tun = ParcelFileDescriptor.dup(descriptors[0]);
            } finally {
                Os.close(descriptors[0]);
            }
            Log.i(TAG, "IPv4 IKE routes ready for " + resolved);
            success = true;
            return result;
        } finally {
            if (!success) result.close();
        }
    }

    int getFd() {
        return tun.getFd();
    }

    @Override
    public void close() {
        // Closing the control socket tells the helper to delete only its own rules.
        // It also receives EOF if Android kills the app process.
        if (control != null) {
            try { control.close(); } catch (IOException ignored) {}
            control = null;
        }
        if (tun != null) {
            try { tun.close(); } catch (IOException ignored) {}
            tun = null;
        }
        if (helper != null && Build.VERSION.SDK_INT >= 26) {
            try {
                if (!helper.waitFor(5, TimeUnit.SECONDS)) {
                    Log.w(TAG, "Helper cleanup has not completed; check root log");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            helper = null;
        }
    }
}
