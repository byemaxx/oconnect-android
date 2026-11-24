/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package app.openconnect.core;

import android.content.Context;
import android.os.Build;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/** Explicit, bounded root/helper preflight, independent of Android VPN permission. */
public final class RootAccess {
    private RootAccess() {}

    static String helperPath(Context context) throws IOException {
        String path = context.getApplicationInfo().nativeLibraryDir
                + File.separator + "libroot-tun.so";
        if (!new File(path).isFile()) {
            throw new IOException("Root helper missing for this ABI");
        }
        return path;
    }

    static Process start(String... args) throws IOException {
        StringBuilder command = new StringBuilder();
        for (String arg : args) {
            if (command.length() > 0) command.append(' ');
            command.append('\'').append(arg.replace("'", "'\\''")).append('\'');
        }
        return new ProcessBuilder("su", "-c", command.toString())
                .redirectErrorStream(true).start();
    }

    public static void check(Context context) throws IOException {
        runProbe(context, "--probe");
    }

    public static String ensureTun(Context context) throws IOException {
        return runProbe(context, "--ensure-tun");
    }

    private static String runProbe(Context context, String mode) throws IOException {
        if (Build.VERSION.SDK_INT < 26) {
            throw new IOException("Root ePDG mode requires Android 8 or newer");
        }
        String path = helperPath(context);
        Process process;
        try {
            process = start(path, mode);
        } catch (IOException e) {
            throw new IOException("Cannot launch su: " + e.getMessage(), e);
        }
        try {
            if (!process.waitFor(60, TimeUnit.SECONDS)) {
                throw new IOException("Root authorization timed out. Check KernelSU.");
            }
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (output.length() < 2048) output.append(line).append('\n');
                }
            }
            String result = output.toString().trim();
            if (process.exitValue() != 0 || !result.contains("ROOT_TUN_PROBE_OK")) {
                throw new IOException("Root/TUN check failed (exit " + process.exitValue()
                        + "): " + (result.isEmpty() ? "Check KernelSU app permission and profile." : result));
            }
            return result;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Root check interrupted", e);
        } finally {
            if (process.isAlive()) process.destroyForcibly();
        }
    }
}
