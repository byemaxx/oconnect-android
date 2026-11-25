package app.openconnect.core;

import android.content.Context;
import android.os.Build;
import android.os.PersistableBundle;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** On-demand root Binder snapshot. Only fixed-value fields leave the probe. */
public final class CrossSimDiagnostics {
    private static final String PHONE = "com.android.internal.telephony.ITelephony";
    private static final String SUB = "com.android.internal.telephony.ISub";
    private static final String CONFIG = "com.android.internal.telephony.ICarrierConfigLoader";
    private static final String UNKNOWN = "Unknown";
    private static final String PREFIX = "OCONNECT_CROSS_SIM ";

    private CrossSimDiagnostics() {}

    public static Map<String, String> read(Context context) throws IOException, InterruptedException {
        if (Build.VERSION.SDK_INT < 31) throw new IOException("Android 12 or newer is required.");
        Process process = RootAccess.start("/system/bin/env",
                "CLASSPATH=" + context.getApplicationInfo().sourceDir,
                "/system/bin/app_process", "/", CrossSimDiagnostics.class.getName(),
                context.getPackageName());
        try {
            if (!process.waitFor(25, TimeUnit.SECONDS)) {
                throw new IOException("Root diagnostics timed out.");
            }
            Map<String, String> fields = new LinkedHashMap<>();
            boolean complete = false;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if ((PREFIX + "complete").equals(line)) complete = true;
                    if (!line.startsWith(PREFIX)) continue;
                    int separator = line.indexOf('=', PREFIX.length());
                    if (separator > PREFIX.length()) {
                        fields.put(line.substring(PREFIX.length(), separator), line.substring(separator + 1));
                    }
                }
            }
            if (process.exitValue() != 0 || !complete) {
                throw new IOException("Root diagnostics unavailable. Check KernelSU authorization.");
            }
            return fields;
        } finally {
            if (process.isAlive()) process.destroyForcibly();
        }
    }

    public static void main(String[] args) throws ReflectiveOperationException, InterruptedException {
        String packageName = args[0];
        Object subs = FreedomImsProbe.service("isub", SUB);
        int[] active = (int[]) Class.forName(SUB).getMethod("getActiveSubIdList", boolean.class)
                .invoke(subs, false);
        Object phone = FreedomImsProbe.service("phone", PHONE);
        Object config = FreedomImsProbe.service("carrier_config", CONFIG);
        // app_process has no application context for SubscriptionManager's static cache.
        Object defaultData = query(SUB, subs, "getDefaultDataSubId", new Class<?>[0]);
        Object activeData = query(SUB, subs, "getActiveDataSubscriptionId", new Class<?>[0]);
        emit("default", defaultData instanceof Integer && (int) defaultData >= 0 ? defaultData : UNKNOWN);
        emit("active", activeData instanceof Integer && (int) activeData >= 0 ? activeData : UNKNOWN);
        emit("dataRoamingEnabled", activeData instanceof Integer
                ? query(PHONE, phone, "isDataRoamingEnabled", (int) activeData) : UNKNOWN);

        Map<Integer, String> preferred = preferredImsTransports();
        for (int id : active) {
            Object slot = query(SUB, subs, "getSlotIndex", id);
            emit("slot." + id, slot);
            emit("preferred." + id, preferred.getOrDefault(slot, UNKNOWN));
            if (slot instanceof Integer && (int) slot >= 0) {
                Object state = query(PHONE, phone, "getServiceStateForSlot",
                        new Class<?>[]{int.class, boolean.class, boolean.class, String.class, String.class},
                        slot, true, true, packageName, null);
                emit("roaming." + id, query("android.telephony.ServiceState", state,
                        "getDataRoaming", new Class<?>[0]));
            }
            emit("enabled." + id, query(PHONE, phone, "isCrossSimCallingEnabledByUser", id));
            Object bundle = query(CONFIG, config, "getConfigForSubIdWithFeature",
                    new Class<?>[]{int.class, String.class, String.class}, id, packageName, null);
            String key = "carrier_cross_sim_ims_available_bool";
            emit("eligible." + id, bundle instanceof PersistableBundle
                    && ((PersistableBundle) bundle).containsKey(key)
                    ? ((PersistableBundle) bundle).getBoolean(key) : UNKNOWN);

            Object registered = query(PHONE, phone, "isImsRegistered", id);
            Object tech = query(PHONE, phone, "getImsRegTechnologyForMmTel", id);
            emit("registered." + id, registered);
            emit("tech." + id, technology(registered, tech));
            // CAPABILITY_TYPE_VOICE is 1; query availability for the observed access.
            emit("voice." + id, Boolean.FALSE.equals(registered) ? false
                    : Boolean.TRUE.equals(registered) && tech instanceof Integer && (int) tech >= 0
                    ? query(PHONE, phone, "isAvailable", new Class<?>[]{int.class, int.class, int.class},
                            id, 1, tech) : UNKNOWN);
        }
        System.out.println(PREFIX + "complete");
    }

    private static Map<Integer, String> preferredImsTransports() throws InterruptedException {
        try {
            Process dump = new ProcessBuilder("/system/bin/timeout", "8", "/system/bin/dumpsys",
                    "activity", "service", "TelephonyDebugService").redirectErrorStream(true).start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(dump.getInputStream()))) {
                Map<Integer, String> result = parsePreferredImsTransports(reader);
                if (dump.waitFor() == 0) return result;
            } finally {
                if (dump.isAlive()) dump.destroyForcibly();
            }
        } catch (IOException ignored) {
            // This vendor dump can be unavailable even if the Binder queries work.
        }
        return new LinkedHashMap<>();
    }

    static Map<Integer, String> parsePreferredImsTransports(BufferedReader reader) throws IOException {
        Pattern header = Pattern.compile("AccessNetworksManager-([0-9]+):");
        Pattern ims = Pattern.compile("ims: (WWAN|WLAN)");
        Map<Integer, String> transports = new LinkedHashMap<>();
        int slot = -1;
        boolean preferred = false;
        String line;
        while ((line = reader.readLine()) != null) {
            String value = line.trim();
            Matcher manager = header.matcher(value);
            if (manager.matches()) {
                slot = Integer.parseInt(manager.group(1));
                preferred = false;
            } else if (slot >= 0 && "preferred transports=".equals(value)) {
                preferred = true;
            } else if ("Local logs=".equals(value)) {
                slot = -1;
                preferred = false;
            } else if (preferred) {
                Matcher transport = ims.matcher(value);
                if (transport.matches()) {
                    transports.put(slot, transport.group(1));
                    preferred = false;
                }
            }
        }
        return transports;
    }

    static String technology(Object registered, Object tech) {
        if (Boolean.FALSE.equals(registered)) return "Unregistered";
        if (!Boolean.TRUE.equals(registered) || !(tech instanceof Integer)) return UNKNOWN;
        // ImsRegistrationImplBase REGISTRATION_TECH_* values on Android 16.
        switch ((int) tech) {
            case 0: return "LTE";
            case 1: return "IWLAN";
            case 2: return "CROSS_SIM";
            case 3: return "NR";
            case 4: return "3G";
            default: return UNKNOWN;
        }
    }

    private static Object query(String type, Object service, String method, int id) {
        return id < 0 ? UNKNOWN : query(type, service, method, new Class<?>[]{int.class}, id);
    }

    private static Object query(String type, Object service, String method, Class<?>[] types, Object... args) {
        if (service == null || UNKNOWN.equals(service)) return UNKNOWN;
        try {
            Method getter = Class.forName(type).getMethod(method, types);
            Object value = getter.invoke(service, args);
            return value == null ? UNKNOWN : value;
        } catch (ReflectiveOperationException | RuntimeException e) {
            return UNKNOWN;
        }
    }

    private static void emit(String key, Object value) {
        System.out.println(PREFIX + key + "=" + value);
    }
}
