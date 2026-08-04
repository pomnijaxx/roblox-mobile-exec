package roblox.executor;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Java side of the UNC surface. The native engine never links curl/TLS —
 * every request()/notification goes through here, so certificate handling,
 * proxy settings and threading stay 100% platform-managed.
 *
 * Expected by unc_api.cpp (via JNI FindClass on "roblox/executor/ScriptLoader"):
 *   static String requestHttp(String url, String method, String body)
 *   static void   toast(String title, String msg)
 *   static void   onFrame()                 // called after each nativeExec
 */
public final class ScriptLoader {

    private static final String TAG = "RobloxExec.ScriptLoader";

    private static volatile android.content.Context sAppContext;
    private static final ExecutorService HTTP_POOL = Executors.newFixedThreadPool(2);

    private ScriptLoader() {
    }

    /** Called by the injected Application.onCreate() before nativeInit. */
    public static void attach(android.content.Context context) {
        sAppContext = context != null ? context.getApplicationContext() : null;
        Log.i(TAG, "attached (context=" + sAppContext + ")");
    }

    /** Synchronous HTTP — invoked on a native worker thread. */
    @SuppressWarnings("unused") // called from native via JNI
    public static String requestHttp(String url, String method, String body) {
        HttpURLConnection conn = null;
        try {
            if (url == null || url.isEmpty()) url = "https://www.roblox.com";
            String m = method == null ? "GET" : method.trim().toUpperCase();
            if (m.isEmpty()) m = "GET";

            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod(m);
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("User-Agent", "RobloxExec/0.830.5 (Luau; arm64-v8a)");
            conn.setRequestProperty("Accept", "*/*");

            if (!"GET".equals(m) && !"HEAD".equals(m) && body != null && !body.isEmpty()) {
                conn.setDoOutput(true);
                byte[] payload = body.getBytes("UTF-8");
                conn.setFixedLengthStreamingMode(payload.length);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(payload);
                }
            }

            int code = conn.getResponseCode();
            InputStream in = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            if (in != null) {
                byte[] tmp = new byte[8192];
                int n;
                while ((n = in.read(tmp)) > 0) buf.write(tmp, 0, n);
                in.close();
            }

            StringBuilder hdrs = new StringBuilder();
            for (int i = 0; ; i++) {
                String k = conn.getHeaderFieldKey(i);
                if (k == null) break;
                hdrs.append(k).append(": ").append(conn.getHeaderField(i)).append('\n');
            }

            String status = (code >= 200 && code < 300) ? "OK" : "ERR";
            return "{\"Success\":" + (code >= 200 && code < 300)
                    + ",\"StatusCode\":" + code
                    + ",\"StatusMessage\":\"" + escape(status) + "\""
                    + ",\"Headers\":\"" + escape(hdrs.toString()) + "\""
                    + ",\"Body\":\"" + escape(buf.toString("UTF-8")) + "\"}";
        } catch (Throwable t) {
            return "{\"Success\":false,\"StatusCode\":0"
                    + ",\"StatusMessage\":\"" + escape(t.getClass().getSimpleName()
                    + ": " + t.getMessage()) + "\""
                    + ",\"Headers\":\"\",\"Body\":\"\"}";
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** Toast on the main thread (never called off the UI thread). */
    @SuppressWarnings("unused") // called from native via JNI
    public static void toast(final String title, final String msg) {
        final android.content.Context ctx = sAppContext;
        if (ctx == null) return;
        final String text = (title == null ? "" : title)
                + ((msg == null || msg.isEmpty()) ? "" : "\n" + msg);
        new Handler(Looper.getMainLooper()).post(() -> {
            try {
                Toast.makeText(ctx, text, Toast.LENGTH_LONG).show();
            } catch (Throwable ignored) {
                Log.w(TAG, "toast failed", ignored);
            }
        });
    }

    /** Called by native after each nativeExec so Java can drain queues. */
    @SuppressWarnings("unused") // called from native via JNI
    public static void onFrame() {
        // future: script queue drain / heartbeat
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "");
    }
}
