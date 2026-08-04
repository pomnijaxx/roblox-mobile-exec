package roblox.executor;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Floating script console (Delta/ArceusX style).
 *
 * Entry points (all called from the injected Application path):
 *   ensureNotification(Context)  -> persistent notification; tap opens the console
 *   showOverlay(Context)         -> attach the floating window (needs SYSTEM_ALERT_WINDOW)
 *   appendLog(String)            -> pushed from ScriptLoader/toast paths
 *
 * Framework APIs only — no AndroidX, so it compiles against plain android.jar
 * and can be smali'd with javac + d8 + baksmali in CI.
 */
public final class ExecutorUI {

    public static final int NOTIF_ID = 0x4545;
    private static final String CHANNEL_ID = "robloxexec";
    private static final String TAG = "RobloxExec.UI";
    private static final int MAX_LOG_CHARS = 20000;

    private static final Handler UI = new Handler(Looper.getMainLooper());

    private static WindowManager sWm;
    private static View sOverlay;
    private static EditText sScript;
    private static TextView sLog;

    private ExecutorUI() {
    }

    /** Persistent notification; tapping it opens the console. */
    public static void ensureNotification(final Context ctx) {
        if (ctx == null) return;
        UI.post(() -> {
            try {
                Context app = ctx.getApplicationContext();
                NotificationManager nm =
                        (NotificationManager) app.getSystemService(Context.NOTIFICATION_SERVICE);
                if (nm == null) return;

                if (Build.VERSION.SDK_INT >= 26) {
                    NotificationChannel ch = new NotificationChannel(
                            CHANNEL_ID, "RobloxExec",
                            NotificationManager.IMPORTANCE_LOW);
                    ch.setDescription("Script executor console");
                    nm.createNotificationChannel(ch);
                }

                Intent open = new Intent(app, ExecutorUIActivity.class)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                int flags = 0;
                if (Build.VERSION.SDK_INT >= 23) flags |= PendingIntent.FLAG_IMMUTABLE;
                PendingIntent pi = PendingIntent.getActivity(app, 0, open, flags);

                Notification.Builder b = Build.VERSION.SDK_INT >= 26
                        ? new Notification.Builder(app, CHANNEL_ID)
                        : new Notification.Builder(app);
                b.setSmallIcon(android.R.drawable.ic_menu_edit)
                        .setContentTitle("RobloxExec")
                        .setContentText("Abrir console de scripts")
                        .setOngoing(true)
                        .setContentIntent(pi);

                nm.notify(NOTIF_ID, b.build());
                Log.i(TAG, "notification posted (id=" + NOTIF_ID + ")");
            } catch (Throwable t) {
                Log.w(TAG, "ensureNotification failed", t);
            }
        });
    }

    /** Attach the floating window. Opens the overlay-permission settings if needed. */
    public static void showOverlay(final Context ctx) {
        if (ctx == null) return;
        UI.post(() -> {
            try {
                if (sOverlay != null) return;
                Context app = ctx.getApplicationContext();

                if (!canDrawOverlays(app)) {
                    appendLog("[ui] overlay permission required — opening settings");
                    openOverlaySettings(app);
                    return;
                }

                sWm = (WindowManager) app.getSystemService(Context.WINDOW_SERVICE);
                if (sWm == null) return;

                View v = buildConsole(app);
                sOverlay = v;

                int h = (int) (app.getResources().getDisplayMetrics().heightPixels * 0.72f);
                int type = Build.VERSION.SDK_INT >= 26
                        ? WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                        : WindowManager.LayoutParams.TYPE_PHONE;
                WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
                        WindowManager.LayoutParams.MATCH_PARENT, h, type,
                        WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                        PixelFormat.TRANSLUCENT);
                lp.gravity = Gravity.TOP | Gravity.CENTER_HORIZONTAL;
                lp.softInputMode = WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE;
                sWm.addView(v, lp);

                appendLog("[ui] console ready — paste script and hit Execute");
            } catch (Throwable t) {
                Log.w(TAG, "showOverlay failed", t);
            }
        });
    }

    /** Detach the floating window. */
    public static void hideOverlay() {
        UI.post(() -> {
            try {
                if (sWm != null && sOverlay != null) sWm.removeView(sOverlay);
            } catch (Throwable ignored) {
                // view may already be detached
            }
            sOverlay = null;
            sScript = null;
            sLog = null;
        });
    }

    /** Append a line to the console log (thread-safe). */
    public static void appendLog(final String line) {
        UI.post(() -> {
            if (sLog == null) return;
            try {
                sLog.append(line == null ? "null" : line);
                sLog.append('\n');
                if (sLog.length() > MAX_LOG_CHARS) {
                    sLog.getEditableText().delete(0, sLog.length() - MAX_LOG_CHARS / 2);
                }
            } catch (Throwable t) {
                Log.w(TAG, "appendLog failed", t);
            }
        });
    }

    // ----------------------------------------------------------------------

    private static boolean canDrawOverlays(Context app) {
        if (Build.VERSION.SDK_INT < 23) return true;
        try {
            return Settings.canDrawOverlays(app);
        } catch (Throwable t) {
            return true; // some OEMs stub the API out
        }
    }

    private static void openOverlaySettings(Context app) {
        try {
            Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:" + app.getPackageName()))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            app.startActivity(i);
        } catch (Throwable t) {
            Log.w(TAG, "could not open overlay settings", t);
        }
    }

    private static View buildConsole(Context app) {
        int pad = dp(app, 10);

        LinearLayout root = new LinearLayout(app);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xE6121215);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(app);
        title.setText("RobloxExec console");
        title.setTextColor(Color.WHITE);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        // script editor
        sScript = new EditText(app);
        sScript.setHint("-- paste your script here");
        sScript.setTextColor(Color.WHITE);
        sScript.setHintTextColor(0xFF888888);
        sScript.setTypeface(Typeface.MONOSPACE);
        sScript.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        sScript.setBackgroundColor(0xE61B1B22);
        sScript.setSingleLine(false);
        sScript.setMinLines(10);
        sScript.setGravity(Gravity.TOP | Gravity.START);
        LinearLayout.LayoutParams editLp =
                new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.0f);
        root.addView(sScript, editLp);

        // buttons row
        LinearLayout row = new LinearLayout(app);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER);

        Button exec = new Button(app);
        exec.setText("Execute");
        exec.setTextColor(Color.WHITE);
        exec.setBackgroundColor(0xFF1E7E34);
        exec.setOnClickListener(v -> doExecute());

        Button clear = new Button(app);
        clear.setText("Clear");
        clear.setTextColor(Color.WHITE);
        clear.setBackgroundColor(0xFF3A3A44);
        clear.setOnClickListener(v -> {
            if (sScript != null) sScript.setText("");
        });

        Button close = new Button(app);
        close.setText("Close");
        close.setTextColor(Color.WHITE);
        close.setBackgroundColor(0xFF8C2F2F);
        close.setOnClickListener(v -> hideOverlay());

        row.addView(exec, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1.0f));
        row.addView(clear, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1.0f));
        row.addView(close, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1.0f));
        root.addView(row);

        // log area
        ScrollView scroller = new ScrollView(app);
        sLog = new TextView(app);
        sLog.setTextColor(0xFFA8D8A8);
        sLog.setTypeface(Typeface.MONOSPACE);
        sLog.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        sLog.setBackgroundColor(0xE6101015);
        sLog.setText("RobloxExec v1.0\n");
        scroller.addView(sLog);
        LinearLayout.LayoutParams logLp =
                new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, dp(app, 180));
        root.addView(scroller, logLp);

        return root;
    }

    private static void doExecute() {
        if (sScript == null) return;
        String src = sScript.getText().toString();
        if (src.trim().isEmpty()) {
            appendLog("[exec] empty script");
            return;
        }
        appendLog("[exec] executing " + src.length() + " bytes...");
        new Thread(() -> {
            int rc = Executor.nativeExec(src);
            appendLog("[exec] " + (rc == 0 ? "done (0)" : "error code " + rc));
        }, "robloxexec-run").start();
    }

    private static int dp(Context app, int value) {
        return (int) TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value, app.getResources().getDisplayMetrics());
    }
}
