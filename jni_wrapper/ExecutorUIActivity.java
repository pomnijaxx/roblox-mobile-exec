package roblox.executor;

import android.app.Activity;
import android.os.Bundle;

/**
 * Transparent launcher activity used as the notification tap target.
 * Just attaches the floating console and finishes. Declared in the manifest
 * by patcher.py (exported=false, Translucent theme).
 */
public final class ExecutorUIActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            ExecutorUI.showOverlay(this);
        } finally {
            finish();
        }
    }
}
