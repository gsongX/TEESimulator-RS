package android.security.maintenance;

import android.os.IBinder;
import android.os.IInterface;

public interface IKeystoreMaintenance extends IInterface {
    String DESCRIPTOR = "android.security.maintenance.IKeystoreMaintenance";

    class Stub {
        public static IKeystoreMaintenance asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
