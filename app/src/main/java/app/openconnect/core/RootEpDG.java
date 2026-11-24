/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package app.openconnect.core;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;
import org.infradead.libopenconnect.LibOpenConnect;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.UUID;

/** Keeps the authenticated OpenConnect session in the app; only TUN creation and
 * narrowly scoped routing are privileged. No VPN NetworkAgent is established. */
final class RootEpDG implements Closeable {
    static final String ENABLED = "root_epdg_mode";
    static final String TARGET = "root_epdg_ipv4";
    private static final String TAG = "OConnectRoot";
    private final LocalSocket control;
    private final ParcelFileDescriptor tun;
    private final Process helper;

    private RootEpDG(LocalSocket control, ParcelFileDescriptor tun, Process helper) {
        this.control = control;
        this.tun = tun;
        this.helper = helper;
    }

    static void requireWifi(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) throw new IllegalArgumentException("Connectivity service unavailable");
        Network active = cm.getActiveNetwork();
        NetworkCapabilities caps = active == null ? null : cm.getNetworkCapabilities(active);
        if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            throw new IllegalArgumentException("Root ePDG mode requires active Wi-Fi and no system VPN");
        }
        for (Network n : cm.getAllNetworks()) {
            NetworkCapabilities nc = cm.getNetworkCapabilities(n);
            if (nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                throw new IllegalArgumentException("Disconnect the existing Android VPN first");
            }
        }
    }

    static RootEpDG open(Context context, LibOpenConnect.IPInfo ip, String target) throws IOException {
        requireWifi(context);
        target = RootRoutePolicy.target(target);
        RootRoutePolicy.ipv4(ip.addr);
        int prefix = RootRoutePolicy.prefix(ip.netmask);
        RootRoutePolicy.checkServerRoutes(target, ip.splitIncludes, ip.splitExcludes);
        if (target.equals(ip.gatewayAddr) || target.equals(ip.addr)) {
            throw new IllegalArgumentException("ePDG target cannot be the VPN gateway or local address");
        }
        int mtu = Math.min(1500, Math.max(576, ip.MTU));
        File bin = new File(context.getApplicationInfo().nativeLibraryDir, "libroot-epdg.so");
        if (!bin.isFile() || !bin.canExecute()) {
            throw new IOException("Root helper missing: rebuild with make -C external install");
        }
        String name = "oconnect-root-" + UUID.randomUUID();
        String cmd = quote(bin.getAbsolutePath()) + " " + quote(name) + " "
                + android.os.Process.myUid() + " " + ip.addr + " " + prefix + " " + mtu + " " + target;
        Process process = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
        // Drain the helper's output, which contains only routing diagnostics.
        Thread reader = new Thread(() -> {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = in.readLine()) != null) Log.i(TAG, line);
            } catch (IOException e) {
                Log.w(TAG, "Helper log closed", e);
            }
        }, "RootEpDG-log");
        reader.setDaemon(true);
        reader.start();

        LocalSocket socket = null;
        ParcelFileDescriptor pfd = null;
        boolean ok = false;
        try {
            long deadline = SystemClock.elapsedRealtime() + 60000;
            while (SystemClock.elapsedRealtime() < deadline) {
                try {
                    process.exitValue();
                    throw new IOException("Root helper exited; check logcat -s OConnectRoot");
                } catch (IllegalThreadStateException running) {
                    // Root approval or the helper may still be starting.
                }
                LocalSocket attempt = new LocalSocket();
                try {
                    attempt.connect(new LocalSocketAddress(name, LocalSocketAddress.Namespace.ABSTRACT));
                    socket = attempt;
                    break;
                } catch (IOException e) {
                    attempt.close();
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Root setup interrupted", interrupted);
                    }
                }
            }
            if (socket == null) throw new IOException("Timed out waiting for root helper");
            if (socket.getPeerCredentials().getUid() != 0) throw new IOException("Root helper UID mismatch");
            socket.setSoTimeout(30000);
            if (socket.getInputStream().read() != 1) {
                throw new IOException("Root route setup failed; check logcat -s OConnectRoot");
            }
            FileDescriptor[] fds = socket.getAncillaryFileDescriptors();
            if (fds == null || fds.length != 1) {
                if (fds != null) for (FileDescriptor fd : fds) closeRaw(fd);
                throw new IOException("Root helper did not return a TUN descriptor");
            }
            try {
                pfd = ParcelFileDescriptor.dup(fds[0]);
            } finally {
                closeRaw(fds[0]);
            }
            ok = true;
            return new RootEpDG(socket, pfd, process);
        } finally {
            if (!ok) {
                if (socket != null) try { socket.close(); } catch (IOException ignored) {}
                if (pfd != null) try { pfd.close(); } catch (IOException ignored) {}
                // The helper rolls back on EOF. If no client ever connected,
                // it has its own accept timeout and has not created routes.
            }
        }
    }

    private static void closeRaw(FileDescriptor fd) {
        try { Os.close(fd); } catch (ErrnoException ignored) {}
    }

    private static String quote(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }

    int fd() { return tun.getFd(); }

    @Override public void close() {
        // Closing the authenticated local control socket triggers exact rollback.
        try { control.close(); } catch (IOException ignored) {}
        try { tun.close(); } catch (IOException ignored) {}
        // Do not SIGKILL the helper: it needs to remove its own rules.
        // Keep the Process reference until the session has ended.
    }
}
