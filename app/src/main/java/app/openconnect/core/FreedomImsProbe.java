package app.openconnect.core;

import android.os.IBinder;


/** Read-only entry point for app_process with the already granted relay root permission. */
public final class FreedomImsProbe {
    private static final String PHONE = "com.android.internal.telephony.ITelephony";
    private static final String SUB = "com.android.internal.telephony.ISub";

    static Object service(String name, String type) throws ReflectiveOperationException {
        Object binder = Class.forName("android.os.ServiceManager")
                .getMethod("getService", String.class).invoke(null, name);
        return Class.forName(type + "$Stub").getMethod("asInterface", IBinder.class)
                .invoke(null, binder);
    }

    public static void main(String[] args) {
        try {
            int target = Integer.parseInt(args[0]);
            Object subService = service("isub", SUB);
            int[] active = (int[]) Class.forName(SUB).getMethod("getActiveSubIdList", boolean.class)
                    .invoke(subService, false);
            for (int id : active) {
                if (id != target) continue;
                Object phone = service("phone", PHONE);
                boolean available = Boolean.TRUE.equals(Class.forName(PHONE)
                        .getMethod("isWifiCallingAvailable", int.class).invoke(phone, id));
                System.out.println(available ? "IMS_WIFI" : "IMS_WAITING");
                return;
            }
            System.out.println("IMS_SUB_INACTIVE");
        } catch (ReflectiveOperationException | RuntimeException e) {
            System.out.println("IMS_INTERFACE_ERROR");
        }
    }
}
