package app.openconnect.core;

import android.content.Context;
import android.os.PersistableBundle;
import android.os.Build;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/** Read-only discovery of the target subscription; no modem configuration changes. */
public final class EpdgDiscovery {
    public static final String TARGET_SIM = "epdg_target_slot";
    private static final String SUB = "com.android.internal.telephony.ISub";
    private static final String PHONE = "com.android.internal.telephony.ITelephony";
    private static final String CONFIG = "com.android.internal.telephony.ICarrierConfigLoader";

    static final class Target {
        final int subId;
        final int slot;
        final String home;
        final Set<String> candidates = new LinkedHashSet<>();
        Target(int subId, int slot, String plmn, String configured) {
            this.subId = subId;
            this.slot = slot;
            home = hostname(plmn);
            for (String value : configured.split("[,\\s]+")) {
                if (validHost(value)) candidates.add(value);
            }
            candidates.add(home);
        }
    }

    static final class Subscription {
        final int subId;
        final Integer slot;
        final String plmn;
        final Boolean wifiCallingEnabled;

        Subscription(int subId, Integer slot, String plmn, Boolean wifiCallingEnabled) {
            this.subId = subId;
            this.slot = slot;
            this.plmn = plmn;
            this.wifiCallingEnabled = wifiCallingEnabled;
        }

        boolean hasTargetDetails() {
            return slot != null && slot >= 0 && plmn != null && plmn.matches("[0-9]{5,6}");
        }
    }

    static Subscription select(List<Subscription> active, String slot) throws IOException {
        final String unavailable = "Target SIM information unavailable. Check root access and Target SIM.";
        if (active == null) throw new IOException(unavailable);
        if (!"auto".equals(slot)) {
            Subscription selected = null;
            boolean unknownSlot = false;
            for (Subscription sim : active) {
                if (sim.slot == null || sim.slot < 0) {
                    unknownSlot = true;
                } else if (Integer.toString(sim.slot).equals(slot)) {
                    if (selected != null) throw new IOException("Multiple active subscriptions match Target SIM.");
                    selected = sim;
                }
            }
            if (selected != null && selected.hasTargetDetails()) return selected;
            if (selected != null || unknownSlot) throw new IOException(unavailable);
            throw new IOException("Selected Target SIM slot is inactive.");
        }
        if (active.size() == 1) {
            Subscription sim = active.get(0);
            if (sim.hasTargetDetails()) return sim;
            throw new IOException(unavailable);
        }
        Subscription selected = null;
        int possible = 0;
        for (Subscription sim : active) {
            if (Boolean.FALSE.equals(sim.wifiCallingEnabled)) continue;
            possible++;
            if (Boolean.TRUE.equals(sim.wifiCallingEnabled) && sim.hasTargetDetails()) selected = sim;
        }
        if (possible == 1 && selected != null) return selected;
        if (possible > 1)
            throw new IOException("Multiple eligible or unknown SIMs. Choose Target SIM in Wi-Fi Calling settings.");
        if (possible == 1) throw new IOException(unavailable);
        throw new IOException("No eligible active target SIM found. Check Target SIM.");
    }

    static boolean validHost(String value) {
        return value.matches("(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
                && value.length() <= 253;
    }

    static String hostname(String plmn) {
        if (!plmn.matches("[0-9]{5,6}")) throw new IllegalArgumentException("Invalid home PLMN");
        String mnc = plmn.substring(3);
        if (mnc.length() == 2) mnc = "0" + mnc;
        return "epdg.epc.mnc" + mnc + ".mcc" + plmn.substring(0, 3) + ".pub.3gppnetwork.org";
    }

    static Target read(Context context, String slot) throws IOException {
        // Timed process waiting and forced cleanup are available from API 26.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            throw new IOException("ePDG discovery requires Android 8 or newer");
        }
        Process process = RootAccess.start("/system/bin/env",
                "CLASSPATH=" + context.getApplicationInfo().sourceDir,
                "/system/bin/app_process", "/", EpdgDiscovery.class.getName(),
                context.getPackageName(), slot);
        try {
            if (!process.waitFor(12, TimeUnit.SECONDS)) throw new IOException("ePDG SIM discovery timed out");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("EPDG_TARGET ")) {
                        String[] fields = line.substring("EPDG_TARGET ".length()).split(" ", 4);
                        if (fields.length >= 3 && process.exitValue() == 0)
                            return new Target(Integer.parseInt(fields[0]), Integer.parseInt(fields[1]),
                                    fields[2], fields.length == 4 ? fields[3] : "");
                    }
                    if (line.startsWith("EPDG_ERROR "))
                        throw new IOException(line.substring("EPDG_ERROR ".length()));
                }
            }
            throw new IOException("Target SIM information unavailable. Check root access and Target SIM.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("ePDG discovery interrupted", e);
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid SIM discovery result", e);
        } finally {
            if (process.isAlive()) process.destroyForcibly();
        }
    }

    private static Object query(String type, Object service, String method, Class<?>[] types, Object... args) {
        try {
            return Class.forName(type).getMethod(method, types).invoke(service, args);
        } catch (ReflectiveOperationException | RuntimeException ignored) { return null; }
    }

    public static void main(String[] args) {
        try {
            String numeric = (String) Class.forName("android.os.SystemProperties")
                    .getMethod("get", String.class).invoke(null, "gsm.sim.operator.numeric");
            String[] operators = numeric.split(",", -1);
            Object subs = FreedomImsProbe.service("isub", SUB);
            int[] ids = (int[]) query(SUB, subs, "getActiveSubIdList", new Class<?>[]{boolean.class}, false);
            Object phone = FreedomImsProbe.service("phone", PHONE);
            List<Subscription> active = null;
            if (ids != null) {
                active = new ArrayList<>(ids.length);
                for (int id : ids) {
                    Object slotValue = query(SUB, subs, "getSlotIndex", new Class<?>[]{int.class}, id);
                    Integer slot = slotValue instanceof Integer ? (Integer) slotValue : null;
                    String plmn = slot != null && slot >= 0 && slot < operators.length ? operators[slot] : null;
                    Object enabled = query(PHONE, phone, "isVoWiFiSettingEnabled", new Class<?>[]{int.class}, id);
                    if (!(enabled instanceof Boolean)) {
                        enabled = query(PHONE, phone, "isWifiCallingEnabledByUser", new Class<?>[]{int.class}, id);
                    }
                    active.add(new Subscription(id, slot, plmn, enabled instanceof Boolean ? (Boolean) enabled : null));
                }
            }
            Subscription selected = select(active, args[1]);
            Object config = FreedomImsProbe.service("carrier_config", CONFIG);
            Object raw = query(CONFIG, config, "getConfigForSubIdWithFeature",
                    new Class<?>[]{int.class, String.class, String.class}, selected.subId, args[0], null);
            String configured = "";
            if (raw instanceof PersistableBundle) {
                PersistableBundle bundle = (PersistableBundle) raw;
                Object roaming = query(PHONE, phone, "getServiceStateForSlot",
                        new Class<?>[]{int.class, boolean.class, boolean.class, String.class, String.class},
                        selected.slot, true, true, args[0], null);
                boolean isRoaming = Boolean.TRUE.equals(query("android.telephony.ServiceState", roaming,
                        "getVoiceRoaming", new Class<?>[0]));
                if (isRoaming) configured = bundle.getString("iwlan.epdg_static_address_roaming_string", "");
                if (configured.isEmpty()) configured = bundle.getString("iwlan.epdg_static_address_string", "");
            }
            System.out.println("EPDG_TARGET " + selected.subId + " " + selected.slot + " "
                    + selected.plmn + " " + configured.replaceAll("[\\r\\n]", ""));
        } catch (IOException e) {
            System.out.println("EPDG_ERROR " + e.getMessage());
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Fail closed rather than selecting an unrelated SIM.
        }
    }
}
