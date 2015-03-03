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
import android.util.Pair;

import com.google.android.gms.gcm.GoogleCloudMessaging;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import cc.bran.bnotify.proto.BNotifyProtos;

public class GcmIntentService extends IntentService {

    private static final String LOG_TAG = "GcmIntentService";
    private static final String PROPERTY_PASSWORD = "password";
    private static final String PAYLOAD_KEY = "payload";
    private static final int AES_KEY_SIZE = 16;
    private static final int SALT_SIZE = 16;
    private static final int GCM_OVERHEAD_SIZE = 16;
    private static final int PBKDF2_ITERATION_COUNT = 4096;
    private static final String CACHED_KEY_FILENAME = "cache.key";
    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA1";

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
                String payload = extras.getString(PAYLOAD_KEY);

                // Base64-decode & parse into an Envelope.
                byte[] envelopeBytes = Base64.decode(payload, Base64.DEFAULT);
                BNotifyProtos.Envelope envelope = BNotifyProtos.Envelope.parseFrom(envelopeBytes);

                // Read parameters from envelope & create GCMParameterSpec.
                byte[] salt = envelope.getSalt().toByteArray();
                byte[] nonce = envelope.getNonce().toByteArray();
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(8*GCM_OVERHEAD_SIZE, nonce);

                // Derive the key (or use the cached key).
                SecretKey key = getKey(salt);

                // Decrypt the message & parse into a Notification.
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
                cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
                byte[] notificationBytes = cipher.doFinal(envelope.getMessage().toByteArray());
                BNotifyProtos.Notification notification = BNotifyProtos.Notification.parseFrom(notificationBytes);

                sendNotification(notification.getTitle(), notification.getText());
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | IllegalArgumentException | NoSuchProviderException exception) {
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

    private SecretKey getKey(byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Try to use cached key first.
        Pair<byte[], SecretKey> cachedSaltAndKey = getCachedSaltAndKey();
        if (cachedSaltAndKey != null && Arrays.equals(salt, cachedSaltAndKey.first)) {
            return cachedSaltAndKey.second;
        }

        // Derive key, store it in the cache, and return it.
        Log.i(LOG_TAG, "Cached key missing or salt mismatch, deriving key");
        String password = getPassword();
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATION_COUNT, 8 * AES_KEY_SIZE);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        SecretKey key = secretKeyFactory.generateSecret(keySpec);
        storeCachedSaltAndKey(salt, key);

        // Encode and de-encode key -- otherwise we get an error:
        //   java.security.InvalidAlgorithmParameterException: no IV set when one expected
        // TODO(bran): why is this necessary? (working around bug in BC? unlikely...)
        byte[] keyMaterial = key.getEncoded();
        key = new SecretKeySpec(keyMaterial, KEY_ALGORITHM);

        return key;
    }

    private Pair<byte[], SecretKey> getCachedSaltAndKey() {
        File cachedKeyFile = new File(getCacheDir(), CACHED_KEY_FILENAME);
        try (FileInputStream cachedKeyStream = new FileInputStream(cachedKeyFile)) {
            byte[] salt = new byte[SALT_SIZE];
            if (cachedKeyStream.read(salt) != SALT_SIZE) {
                return null;
            }

            byte[] keyMaterial = new byte[AES_KEY_SIZE];
            if (cachedKeyStream.read(keyMaterial) != AES_KEY_SIZE) {
                return null;
            }

            SecretKey key = new SecretKeySpec(keyMaterial, KEY_ALGORITHM);
            return new Pair<>(salt, key);
        } catch (IOException exception) {
            Log.w(LOG_TAG, "Error reading cached key", exception);
            return null;
        }
    }

    private boolean storeCachedSaltAndKey(byte[] salt, SecretKey key) {
        assert(salt.length == SALT_SIZE);

        File cachedKeyFile = new File(getCacheDir(), CACHED_KEY_FILENAME);
        try (FileOutputStream cachedKeyStream = new FileOutputStream(cachedKeyFile)) {
            cachedKeyStream.write(salt);
            byte[] keyMaterial = key.getEncoded();
            cachedKeyStream.write(keyMaterial);
            return true;
        } catch (IOException exception) {
            Log.w(LOG_TAG, "Error storing cached key", exception);
            return false;
        }
    }

    private String getPassword() {
        SharedPreferences prefs = getGCMPreferences();
        return prefs.getString(PROPERTY_PASSWORD, "");
    }

    private SharedPreferences getGCMPreferences() {
        return getSharedPreferences(SettingsActivity.class.getSimpleName(), Context.MODE_PRIVATE);
    }
}
