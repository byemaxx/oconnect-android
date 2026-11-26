package app.openconnect.core;

import android.content.Context;
import android.os.PersistableBundle;
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
        final String home;
        final Set<String> candidates = new LinkedHashSet<>();
        Target(int subId, String plmn, String configured) {
            this.subId = subId;
            home = hostname(plmn);
            for (String value : configured.split("[,\\s]+")) {
                if (validHost(value)) candidates.add(value);
            }
            candidates.add(home);
        }
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
                        String[] fields = line.substring(12).split(" ", 3);
                        if (fields.length >= 2 && process.exitValue() == 0)
                            return new Target(Integer.parseInt(fields[0]), fields[1], fields.length == 3 ? fields[2] : "");
                    }
                    if (line.equals("EPDG_AMBIGUOUS"))
                        throw new IOException("Multiple eligible or unknown SIMs. Choose Target SIM in Wi-Fi Calling settings.");
                }
            }
            throw new IOException("No eligible active target SIM found. Check root access and Target SIM.");
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
            Object config = FreedomImsProbe.service("carrier_config", CONFIG);
            List<String> all = new ArrayList<>(), eligible = new ArrayList<>();
            int unknown = 0;
            for (int id : ids) {
                Object slotValue = query(SUB, subs, "getSlotIndex", new Class<?>[]{int.class}, id);
                if (!(slotValue instanceof Integer)) continue;
                int slot = (int) slotValue;
                if (slot < 0 || slot >= operators.length || !operators[slot].matches("[0-9]{5,6}")) continue;
                if (!"auto".equals(args[1]) && !Integer.toString(slot).equals(args[1])) continue;
                Object raw = query(CONFIG, config, "getConfigForSubIdWithFeature",
                        new Class<?>[]{int.class, String.class, String.class}, id, args[0], null);
                PersistableBundle bundle = raw instanceof PersistableBundle ? (PersistableBundle) raw : null;
                String configured = "";
                if (bundle != null) {
                    Object roaming = query(PHONE, phone, "getServiceStateForSlot",
                            new Class<?>[]{int.class, boolean.class, boolean.class, String.class, String.class},
                            slot, true, true, args[0], null);
                    boolean isRoaming = Boolean.TRUE.equals(query("android.telephony.ServiceState", roaming,
                            "getVoiceRoaming", new Class<?>[0]));
                    if (isRoaming) configured = bundle.getString("iwlan.epdg_static_address_roaming_string", "");
                    if (configured.isEmpty()) configured = bundle.getString("iwlan.epdg_static_address_string", "");
                }
                String item = id + " " + operators[slot] + " " + configured.replaceAll("[\\r\\n]", "");
                all.add(item);
                Object enabled = query(PHONE, phone, "isWifiCallingEnabledByUser", new Class<?>[]{int.class}, id);
                if (Boolean.TRUE.equals(enabled)) eligible.add(item);
                else if (!(enabled instanceof Boolean)) unknown++;
            }
            if (all.size() == 1) System.out.println("EPDG_TARGET " + all.get(0));
            else if (eligible.size() == 1 && unknown == 0) System.out.println("EPDG_TARGET " + eligible.get(0));
            else if (all.size() > 1) System.out.println("EPDG_AMBIGUOUS");
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Fail closed rather than selecting an unrelated SIM.
        }
    }
}
