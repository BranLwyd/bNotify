package cc.bran.bnotify;

import android.app.IntentService;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import com.google.android.gms.gcm.GoogleCloudMessaging;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class GcmIntentService extends IntentService {

    private static final String LOG_TAG = "GcmIntentService";
    private static final String PROPERTY_PASSWORD = "password";
    private static final String PAYLOAD_KEY = "payload";
    private static final int AES_KEY_SIZE = 16; // TODO(bran): find a better source for this
    private static final int AES_BLOCK_SIZE = 16; // TODO(bran): find a better source for this
    private static final int PBKDF2_ITERATION_COUNT = 4096;

    private final AtomicInteger nextId;

    public GcmIntentService() {
        super("GcmIntentService");

        this.nextId = new AtomicInteger(0);
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        try {
            GoogleCloudMessaging gcm = GoogleCloudMessaging.getInstance(this);
            Bundle extras = intent.getExtras();
            String messageType = gcm.getMessageType(intent);

            if (GoogleCloudMessaging.MESSAGE_TYPE_MESSAGE.equals(messageType) && !extras.isEmpty()) {
                String base64Payload = extras.getString(PAYLOAD_KEY);

                // Base64-decode to encrypted payload bytes.
                byte[] encryptedPayload = Base64.decode(base64Payload, Base64.DEFAULT);

                // Derive encryption key from password and salt, pull IV from payload.
                String password = getPassword();
                byte[] salt = Arrays.copyOf(encryptedPayload, AES_BLOCK_SIZE);
                PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATION_COUNT, 8 * AES_KEY_SIZE);
                SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                SecretKey key = secretKeyFactory.generateSecret(keySpec);

                IvParameterSpec iv = new IvParameterSpec(encryptedPayload, AES_BLOCK_SIZE, AES_BLOCK_SIZE);

                // Decrypt the message.
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, key, iv);
                byte[] payload = cipher.doFinal(encryptedPayload, 2*AES_BLOCK_SIZE, encryptedPayload.length - 2*AES_BLOCK_SIZE);

                // Parse the payload.
                JSONObject message = new JSONObject(new String(payload, "UTF-8"));
                String title = message.getString("title");
                String text = message.getString("text");

                sendNotification(title, text);
            }
        } catch (Exception exception) {
            // TODO(bran): use a multi-catch instead
            Log.e(LOG_TAG, "Error showing notification", exception);
        } finally {
            GcmBroadcastReceiver.completeWakefulIntent(intent);
        }
    }

    private void sendNotification(String title, String text) {
        NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        PendingIntent contentIntent = PendingIntent.getActivity(this, 0, new Intent(this, SettingsActivity.class), 0);

        int notificationId = nextId.getAndIncrement();
        Notification notification = new Notification.Builder(this)
                .setSmallIcon(R.drawable.logo_white)
                .setContentTitle(title)
                .setStyle(new Notification.BigTextStyle()
                        .bigText(text))
                .setContentText(text)
                .setContentIntent(contentIntent)
                .setVibrate(new long[]{0, 300, 200, 300})
                .build();

        notificationManager.notify(notificationId, notification);
    }

    private String getPassword() {
        SharedPreferences prefs = getGCMPreferences();
        return prefs.getString(PROPERTY_PASSWORD, "");
    }

    private SharedPreferences getGCMPreferences() {
        return getSharedPreferences(SettingsActivity.class.getSimpleName(), Context.MODE_PRIVATE);
    }
}
