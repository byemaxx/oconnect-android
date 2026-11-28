package app.openconnect.core;

import android.content.Context;
import android.os.Build;
import android.os.SystemClock;
import android.telephony.ServiceState;
import android.telephony.TelephonyManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import app.openconnect.R;

public final class WifiCallingRestart {
    private static final String PHONE = "com.android.internal.telephony.ITelephony";
    private static final String SUB = "com.android.internal.telephony.ISub";
    private static final String RESULT = "WFC_RESTART ";
    private static final AtomicBoolean RUNNING = new AtomicBoolean();
    private static Process pending;

    private WifiCallingRestart() {}

    public static String request(Context context, String slot) throws IOException, InterruptedException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return context.getString(R.string.wfc_restart_failed);
        }
        if (!RUNNING.compareAndSet(false, true)) {
            return context.getString(R.string.wfc_restart_timeout);
        }
        try {
            if (pending != null && pending.isAlive()) {
                return context.getString(R.string.wfc_restart_timeout);
            }
            EpdgDiscovery.Target target = EpdgDiscovery.read(context, slot);
            pending = RootAccess.start("/system/bin/env",
                    "CLASSPATH=" + context.getApplicationInfo().sourceDir,
                    "/system/bin/app_process", "/", WifiCallingRestart.class.getName(),
                    context.getPackageName(), Integer.toString(target.subId), Integer.toString(target.slot));
            // Allow the helper to restore the Wi-Fi Calling capability even if the UI times out.
            if (!pending.waitFor(30, TimeUnit.SECONDS)) {
                return context.getString(R.string.wfc_restart_timeout);
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(pending.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.startsWith(RESULT)) continue;
                    switch (line.substring(RESULT.length())) {
                        case "REQUESTED":
                            return context.getString(R.string.wfc_restart_requested, target.slot + 1);
                        case "BUSY":
                            return context.getString(R.string.wfc_restart_busy);
                        case "DISABLED":
                            return context.getString(R.string.wfc_restart_disabled);
                        case "RESTORE_FAILED":
                            return context.getString(R.string.wfc_restart_restore_failed);
                        default:
                            return context.getString(R.string.wfc_restart_failed);
                    }
                }
            }
            return context.getString(R.string.wfc_restart_failed);
        } finally {
            RUNNING.set(false);
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println(RESULT + restart(args[0], Integer.parseInt(args[1]), Integer.parseInt(args[2])));
        } catch (ReflectiveOperationException | RuntimeException e) {
            System.out.println(RESULT + "FAILED");
        }
    }

    private static String restart(String packageName, int target, int slot) throws ReflectiveOperationException {
        Class<?> subType = Class.forName(SUB);
        Object subs = FreedomImsProbe.service("isub", SUB);
        int[] active = (int[]) subType.getMethod("getActiveSubIdList", boolean.class).invoke(subs, false);
        if (active == null || Arrays.stream(active).noneMatch(id -> id == target)) return "FAILED";
        Method getSlot = subType.getMethod("getSlotIndex", int.class);

        Class<?> phoneType = Class.forName(PHONE);
        Object phone = FreedomImsProbe.service("phone", PHONE);
        if (!(boolean) phoneType.getMethod("isVoWiFiSettingEnabled", int.class).invoke(phone, target)) {
            return "DISABLED";
        }
        ServiceState state = (ServiceState) phoneType.getMethod("getServiceStateForSlot", int.class,
                boolean.class, boolean.class, String.class, String.class)
                .invoke(phone, slot, true, true, packageName, null);
        if (state == null) return "FAILED";
        boolean roaming = state.getRoaming();
        if (roaming && !(boolean) phoneType.getMethod("isVoWiFiRoamingSettingEnabled", int.class)
                .invoke(phone, target)) {
            return "DISABLED";
        }
        int mode = (int) phoneType.getMethod(roaming ? "getVoWiFiRoamingModeSetting" : "getVoWiFiModeSetting",
                int.class).invoke(phone, target);
        if (mode < 0 || mode > 2) return "FAILED";
        Method set = phoneType.getMethod("setVoWiFiNonPersistent", int.class, boolean.class, int.class);
        Method callState = phoneType.getMethod("getCallStateForSubscription", int.class, String.class, String.class);
        Method emergency = phoneType.getMethod("getEmergencyCallbackMode", int.class);
        for (int subId : active) {
            if ((int) callState.invoke(phone, subId, packageName, null) != TelephonyManager.CALL_STATE_IDLE
                    || (boolean) emergency.invoke(phone, subId)) {
                return "BUSY";
            }
        }
        if ((int) getSlot.invoke(subs, target) != slot) return "FAILED";

        boolean disabled = false;
        boolean restored = false;
        try {
            set.invoke(phone, target, false, mode);
            disabled = true;
            SystemClock.sleep(2000);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // The Binder call may have changed state before throwing.
        } finally {
            try {
                if ((int) getSlot.invoke(subs, target) == slot) {
                    set.invoke(phone, target, true, mode);
                    restored = true;
                }
            } catch (ReflectiveOperationException | RuntimeException ignored) {
                // The caller must distinguish failed restoration from a rejected request.
            }
        }
        if (!restored) return "RESTORE_FAILED";
        return disabled ? "REQUESTED" : "FAILED";
    }
}
