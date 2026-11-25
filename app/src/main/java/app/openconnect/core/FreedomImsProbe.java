package app.openconnect.core;

import android.os.IBinder;

import java.lang.reflect.Method;

/** Read-only entry point for app_process with the already granted relay root permission. */
public final class FreedomImsProbe {
    private static final String PHONE = "com.android.internal.telephony.ITelephony";
    private static final String SUB = "com.android.internal.telephony.ISub";

    private static Object service(String name, String type) throws ReflectiveOperationException {
        Object binder = Class.forName("android.os.ServiceManager")
                .getMethod("getService", String.class).invoke(null, name);
        return Class.forName(type + "$Stub").getMethod("asInterface", IBinder.class)
                .invoke(null, binder);
    }

    public static void main(String[] args) {
        try {
            String numeric = (String) Class.forName("android.os.SystemProperties")
                    .getMethod("get", String.class).invoke(null, "gsm.sim.operator.numeric");
            String[] operators = numeric.split(",", -1);
            Class<?> subscriptions = Class.forName(SUB);
            Object subService = service("isub", SUB);
            int[] active = (int[]) subscriptions.getMethod("getActiveSubIdList", boolean.class)
                    .invoke(subService, false);
            Method getSlot = subscriptions.getMethod("getSlotIndex", int.class);
            Object phone = service("phone", PHONE);
            Class<?> telephony = Class.forName(PHONE);
            boolean found = false;
            for (int id : active) {
                int slot = (int) getSlot.invoke(subService, id);
                if (slot < 0 || slot >= operators.length || !("302490".equals(operators[slot])
                        || "302500".equals(operators[slot]))) continue;
                found = true;
                if (Boolean.TRUE.equals(telephony.getMethod("isWifiCallingAvailable", int.class)
                        .invoke(phone, id))) {
                    System.out.println("IMS_WIFI");
                    return;
                }
            }
            System.out.println(found ? "IMS_WAITING" : "IMS_UNKNOWN");
        } catch (ReflectiveOperationException | RuntimeException e) {
            System.out.println("IMS_UNKNOWN");
        }
    }
}
