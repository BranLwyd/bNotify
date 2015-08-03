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
import com.google.common.io.ByteStreams;
import com.google.protobuf.ByteString;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;

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
  private static final String PROPERTY_REGISTRATION_ID = "registration_id";
  private static final String PROPERTY_PASSWORD = "password";
  private static final String PROPERTY_NEXT_NOTIFICATION_ID = "next_notification_id";
  private static final String PAYLOAD_KEY = "payload";
  private static final int AES_KEY_SIZE = 16;
  private static final int GCM_OVERHEAD_SIZE = 16;
  private static final int PBKDF2_ITERATION_COUNT = 4096;
  private static final String CACHED_KEY_FILENAME = "cache.key";
  private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA1";

  public GcmIntentService() {
    super("GcmIntentService");
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
        byte[] nonce = envelope.getNonce().toByteArray();
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(8 * GCM_OVERHEAD_SIZE, nonce);

        // Decrypt the message & parse into a Notification.
        SecretKey key = getKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        byte[] notificationBytes = cipher.doFinal(envelope.getMessage().toByteArray());
        BNotifyProtos.Notification notification =
            BNotifyProtos.Notification.parseFrom(notificationBytes);

        sendNotification(notification.getTitle(), notification.getText());
      }
    } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException
        | NoSuchPaddingException | InvalidKeyException | BadPaddingException
        | InvalidAlgorithmParameterException | IllegalBlockSizeException | IllegalArgumentException
        | NoSuchProviderException exception) {
      Log.e(LOG_TAG, "Error showing notification", exception);
    } finally {
      GcmBroadcastReceiver.completeWakefulIntent(intent);
    }
  }

  private void sendNotification(String title, String text) {
    NotificationManager notificationManager =
        (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
    PendingIntent contentIntent =
        PendingIntent.getActivity(this, 0, new Intent(this, SettingsActivity.class), 0);

    int notificationId = getNextNotificationId();
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

  private SecretKey getKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    // Try to use cached key first.
    SecretKey key = getCachedKey();
    if (key != null) {
      return key;
    }

    // Derive key, store it in the cache, and return it.
    Log.i(LOG_TAG, "Could not read cached key, deriving...");
    String password = getPassword();
    String registrationId = getRegistrationId();
    byte[] salt = registrationId.getBytes(Charset.forName("UTF-8"));
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt,
        PBKDF2_ITERATION_COUNT, 8 * AES_KEY_SIZE);
    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
    key = secretKeyFactory.generateSecret(keySpec);
    storeCachedKey(key);

    // Per http://stackoverflow.com/questions/11503157/decrypting-error-no-iv-set-when-one-expected:
    //  The above code creates a JCEPBEKey, not an PBKDF2WithHmacSHA1 key. Recreating with the
    //  appropriate algorithm & the key material fixes this.
    return new SecretKeySpec(key.getEncoded(), KEY_ALGORITHM);
  }

  private SecretKey getCachedKey() {
    File cachedKeyFile = new File(getCacheDir(), CACHED_KEY_FILENAME);
    try (FileInputStream cachedKeyStream = new FileInputStream(cachedKeyFile)) {
      byte[] keyBytes = ByteStreams.toByteArray(cachedKeyStream);
      return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    } catch (IOException exception) {
      Log.w(LOG_TAG, "Error reading cached key", exception);
      return null;
    }
  }

  private boolean storeCachedKey(SecretKey key) {
    File cachedKeyFile = new File(getCacheDir(), CACHED_KEY_FILENAME);
    try (FileOutputStream cachedKeyStream = new FileOutputStream(cachedKeyFile)) {
      cachedKeyStream.write(key.getEncoded());
      return true;
    } catch (IOException exception) {
      Log.w(LOG_TAG, "Error storing cached key", exception);
      return false;
    }
  }

  private String getRegistrationId() {
    SharedPreferences prefs = getGCMPreferences();
    return prefs.getString(PROPERTY_REGISTRATION_ID, null);
  }

  private int getNextNotificationId() {
    SharedPreferences prefs = getGCMPreferences();

    // Loop until commit succeeds.
    int nextId;
    SharedPreferences.Editor editor;
    do {
      nextId = prefs.getInt(PROPERTY_NEXT_NOTIFICATION_ID, 0);
      editor = prefs.edit();
      editor.putInt(PROPERTY_NEXT_NOTIFICATION_ID, nextId + 1);
    } while(!editor.commit());

    return nextId;
  }

  private String getPassword() {
    SharedPreferences prefs = getGCMPreferences();
    return prefs.getString(PROPERTY_PASSWORD, "");
  }

  private SharedPreferences getGCMPreferences() {
    return getSharedPreferences(SettingsActivity.class.getSimpleName(), Context.MODE_PRIVATE);
  }
}
