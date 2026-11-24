/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package app.openconnect.core;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.system.Os;
import android.util.Log;

import org.infradead.libopenconnect.LibOpenConnect;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
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

    static RootTunnel open(Context context, LibOpenConnect.IPInfo ip, String targets)
            throws Exception {
        if (Build.VERSION.SDK_INT < 26) {
            throw new IOException("Root ePDG mode requires Android 8 or newer");
        }
        ConnectivityManager cm = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network network = cm.getActiveNetwork();
        NetworkCapabilities caps = cm.getNetworkCapabilities(network);
        if (caps == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            throw new IOException("Connect directly to Wi-Fi and disconnect other VPNs first");
        }
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
        Set<String> resolved = new LinkedHashSet<>();
        for (String host : targets.trim().split("[,\\s]+")) {
            if (host.isEmpty()) continue;
            // Only literal addresses or ordinary DNS names; no shell fragments.
            if (!host.matches("[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}")) {
                throw new IOException("Invalid ePDG address or hostname");
            }
            for (InetAddress addr : network.getAllByName(host)) {
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
        int mtu = ip.MTU > 0 ? ip.MTU : 1400;
        if (mtu < 576 || mtu > 9000) throw new IOException("Invalid tunnel MTU");
        String nonce = UUID.randomUUID().toString().replace("-", "");
        String socketName = "oconnect-root-" + nonce;
        String executable = context.getApplicationInfo().nativeLibraryDir
                + File.separator + "libroot-tun.so";
        if (!new File(executable).isFile()) {
            throw new IOException("Root helper missing for this ABI");
        }
        ArrayList<String> args = new ArrayList<>();
        args.add(executable);
        args.add(socketName);
        args.add(Integer.toString(android.os.Process.myUid()));
        args.add(vpnAddress.getHostAddress() + "/" + cidr.len);
        args.add(Integer.toString(mtu));
        args.addAll(resolved);
        StringBuilder command = new StringBuilder();
        for (String arg : args) {
            if (command.length() > 0) command.append(' ');
            command.append('\'').append(arg.replace("'", "'\\''")).append('\'');
        }

        RootTunnel result = new RootTunnel();
        boolean success = false;
        try {
            result.helper = new ProcessBuilder("su", "-c", command.toString())
                    .redirectErrorStream(true).start();
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
