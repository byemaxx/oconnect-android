/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package app.openconnect.core;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
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
    static final String PROFILE_ENDPOINT = "freedom_epdg_endpoint";
    static final String DEFAULT_TARGET = "auto";
    static final String PROFILE_RELAY = "epdg_relay_enabled";
    private static final String TAG = "OConnectRoot";
    private static final int MAX_TARGETS = 8;
    private static final int MAX_DNS_SERVERS_PER_FAMILY = 16;
    private LocalSocket control;
    private ParcelFileDescriptor tun;
    private java.lang.Process helper;
    private volatile int freedomStage;
    private volatile Runnable failureCallback;
    private volatile boolean helperOutputClosed;
    private final java.util.concurrent.atomic.AtomicBoolean failureReported =
            new java.util.concurrent.atomic.AtomicBoolean();

    void watchFailure(Runnable callback) {
        failureCallback = callback;
        if (helperOutputClosed || !helperRunning(helper)) reportHelperFailure();
    }

    int getFreedomStage() {
        return helperOutputClosed || !helperRunning(helper) ? 0 : freedomStage;
    }

    private static boolean helperRunning(Process process) {
        if (process == null) return false;
        try {
            process.exitValue();
            return false;
        } catch (IllegalThreadStateException running) {
            return true;
        }
    }

    private void reportHelperFailure() {
        helperOutputClosed = true;
        freedomStage = 0;
        Runnable failed = failureCallback;
        if (failed != null && failureReported.compareAndSet(false, true)) failed.run();
    }

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
        final int subId;
        final String hostname;
        private ConnectivityManager.NetworkCallback callback;

        private Uplink(ConnectivityManager cm, Network network, Network previous,
                Set<String> targets, String interfaceName, boolean freedomRelay, int subId, String hostname) {
            this.cm = cm;
            this.network = network;
            this.previous = previous;
            this.targets = targets;
            this.interfaceName = interfaceName;
            this.freedomRelay = freedomRelay;
            this.subId = subId;
            this.hostname = hostname;
        }

        void verifyAvailable() throws IOException {
            if (!isWifi(cm.getNetworkCapabilities(network))) {
                throw new IOException("Selected Wi-Fi connection was lost during VPN setup");
            }
            if (!network.equals(cm.getBoundNetworkForProcess())) {
                throw new IOException("Wi-Fi process binding changed during VPN setup");
            }
        }

        void watch(Runnable changed) {
            LinkProperties current = cm.getLinkProperties(network);
            if (current == null) {
                changed.run();
                return;
            }
            callback = new ConnectivityManager.NetworkCallback() {
                @Override
                public void onLost(Network candidate) {
                    if (network.equals(candidate)) {
                        Log.i(TAG, "Selected Wi-Fi lost; request relay reconnect");
                        changed.run();
                    }
                }

                @Override
                public void onLinkPropertiesChanged(Network candidate, LinkProperties links) {
                    if (network.equals(candidate) &&
                            (!java.util.Objects.equals(ipv4Address(current), ipv4Address(links))
                            || !current.getDnsServers().equals(links.getDnsServers())
                            || !java.util.Objects.equals(current.getInterfaceName(), links.getInterfaceName()))) {
                        Log.i(TAG, "Selected Wi-Fi interface, IPv4 or DNS changed; request relay reconnect");
                        changed.run();
                    }
                }
            };
            cm.registerNetworkCallback(new NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(), callback);
        }

        @Override
        public void close() {
            synchronized (RootTunnel.class) {
                if (callback != null) {
                    try { cm.unregisterNetworkCallback(callback); } catch (IllegalArgumentException ignored) {}
                    callback = null;
                }
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

    private static String ipv4Address(LinkProperties links) {
        if (links == null) return null;
        for (LinkAddress address : links.getLinkAddresses()) {
            if (address.getAddress() instanceof Inet4Address) return address.getAddress().getHostAddress();
        }
        return null;
    }

    static boolean hasWifi(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return false;
        for (Network candidate : cm.getAllNetworks()) {
            if (!isWifi(cm.getNetworkCapabilities(candidate))) continue;
            LinkProperties links = cm.getLinkProperties(candidate);
            if (links == null) continue;
            for (LinkAddress address : links.getLinkAddresses()) {
                if (address.getAddress() instanceof Inet4Address) return true;
            }
        }
        return false;
    }

    static synchronized Uplink prepareUplink(Context context, String targets, String targetSlot)
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
        if (input.isEmpty()) input = DEFAULT_TARGET;
        boolean legacy = input.toLowerCase(Locale.ROOT).startsWith("freedom=");
        boolean freedomRelay = legacy || input.toLowerCase(Locale.ROOT).startsWith("epdg=")
                || "auto".equalsIgnoreCase(input);
        Set<String> resolved;
        int subId = -1;
        String hostname = null;
        if (freedomRelay) {
            String endpoint = input.contains("=") ? input.substring(input.indexOf('=') + 1).trim() : input;
            EpdgDiscovery.Target target = EpdgDiscovery.read(context, targetSlot);
            subId = target.subId;
            hostname = target.home;
            if (endpoint.isEmpty() || "auto".equalsIgnoreCase(endpoint)) {
                resolved = null;
                IOException failure = null;
                for (String candidate : target.candidates) {
                    try {
                        resolved = resolveTargets(wifi, candidate);
                        if (!candidate.matches("[0-9.]+")) hostname = candidate;
                        break;
                    } catch (IOException e) { failure = e; }
                }
                if (resolved == null) throw new IOException("No discovered IPv4 ePDG endpoint could be resolved", failure);
            } else {
                resolved = resolveTargets(wifi, endpoint);
                if (EpdgDiscovery.validHost(endpoint) && !endpoint.matches("[0-9.]+")) hostname = endpoint;
            }
        } else {
            // Preserve the legacy direct route-only mode for explicit target lists.
            resolved = resolveTargets(wifi, input);
        }
        Network previous = cm.getBoundNetworkForProcess();
        if (!cm.bindProcessToNetwork(wifi)) {
            throw new IOException("Could not bind OConnect to the selected Wi-Fi network");
        }
        Uplink uplink = new Uplink(cm, wifi, previous, resolved, links.getInterfaceName(), freedomRelay, subId, hostname);
        activeUplink = uplink;
        Log.i(TAG, "Selected physical Wi-Fi: " + uplink.interfaceName
                + "; default network was " + active + "; targets=" + resolved);
        return uplink;
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
        return open(context, ip, uplink, null);
    }

    static RootTunnel open(Context context, LibOpenConnect.IPInfo ip, Uplink uplink,
                           ParcelFileDescriptor androidTun) throws Exception {
        boolean global = androidTun != null;
        // Do not re-evaluate the default network after CSTP authentication.
        // The preflight-selected physical Wi-Fi must still be usable.
        uplink.verifyAvailable();
        if (ip.addr == null || ip.netmask == null) {
            throw new IOException("VPN server did not assign an IPv4 address");
        }
        // Do not replace server-selected split routes with an unrestricted tunnel.
        Set<String> resolved = uplink.targets;
        if (global) {
            String endpoint;
            try {
                endpoint = Ipv4RoutePolicy.firstAllowed(resolved, ip.splitIncludes, ip.splitExcludes);
            } catch (IllegalArgumentException e) {
                throw new IOException("Cannot validate server routes for Freedom relay", e);
            }
            if (endpoint == null) {
                throw new IOException("VPN server routes exclude all Freedom endpoint candidates");
            }
            resolved = Collections.singleton(endpoint);
        } else if (ip.splitIncludes != null && !ip.splitIncludes.isEmpty()) {
            throw new IOException("Root ePDG mode currently requires a full IPv4 VPN");
        } else if (uplink.freedomRelay) {
            // The Freedom helper maps the DNS answer and IKE relay to one endpoint per session.
            resolved = Collections.singleton(resolved.iterator().next());
        }
        InetAddress vpnAddress = InetAddress.getByName(ip.addr);
        if (!(vpnAddress instanceof Inet4Address)) {
            throw new IOException("Invalid VPN IPv4 address");
        }
        CIDRIP cidr = new CIDRIP(ip.addr, ip.netmask);
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
            String wifiAddress = ipv4Address(links);
            if (wifiAddress == null) throw new IOException("Freedom relay requires Wi-Fi IPv4");
            Set<String> dns4 = new LinkedHashSet<>();
            Set<String> dns6 = new LinkedHashSet<>();
            for (InetAddress dns : links.getDnsServers()) {
                if (dns instanceof Inet4Address && dns4.size() < MAX_DNS_SERVERS_PER_FAMILY) {
                    dns4.add(dns.getHostAddress());
                } else if (dns instanceof Inet6Address && dns.isLinkLocalAddress()
                        && dns6.size() < MAX_DNS_SERVERS_PER_FAMILY) {
                    dns6.add(dns.getHostAddress().split("%", 2)[0]);
                }
            }
            if (dns4.isEmpty() && dns6.isEmpty()) {
                throw new IOException("Freedom relay requires Wi-Fi IPv4 or link-local IPv6 DNS");
            }
            Collections.addAll(args, global ? "--epdg-global" : "--epdg-relay",
                    uplink.interfaceName, wifiAddress, dns4.isEmpty() ? "-" : String.join(",", dns4),
                    dns6.isEmpty() ? "-" : String.join(",", dns6), uplink.hostname.toLowerCase(Locale.ROOT));
            Log.i(TAG, "Selected Freedom relay endpoint: " + resolved.iterator().next()
                    + "; Wi-Fi DNS candidates IPv4=" + dns4.size() + " IPv6=" + dns6.size());
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
                    while ((line = reader.readLine()) != null) {
                        if (line.equals("Freedom-stage dns")) {
                            result.freedomStage = Math.max(result.freedomStage, 2);
                        } else if (line.equals("Freedom-stage ike")) {
                            result.freedomStage = Math.max(result.freedomStage, 3);
                        } else if (line.equals("Freedom-stage esp")) {
                            result.freedomStage = 4;
                        }
                        Log.i(TAG, line);
                    }
                } catch (IOException e) {
                    Log.d(TAG, "Helper output closed", e);
                } finally {
                    result.reportHelperFailure();
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
                    if (!helperRunning(proc) || SystemClock.elapsedRealtime() >= deadline) {
                        throw new IOException("Root helper did not start; check KernelSU and logcat", e);
                    }
                    SystemClock.sleep(200);
                }
            }
            if (result.control.getPeerCredentials().getUid() != 0) {
                throw new IOException("Root helper peer UID is not zero");
            }
            result.control.setSoTimeout(60000);
            if (global) {
                result.control.setFileDescriptorsForSend(new FileDescriptor[]{androidTun.getFileDescriptor()});
                result.control.getOutputStream().write(1);
            }
            if (result.control.getInputStream().read() != 1) {
                throw new IOException("Root helper failed to configure tunnel; check logcat");
            }
            if (uplink.freedomRelay && result.freedomStage == 0) result.freedomStage = 1;
            if (global) {
                success = true;
                return result;
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
        failureCallback = null;
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
