package cc.bran.bnotify;

import android.app.Activity;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.EditText;
import android.widget.TextView;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.iid.InstanceIdResult;

import java.io.File;

public class SettingsActivity extends Activity {

  private static final String PROPERTY_REGISTRATION_ID = "registration_id";
  private static final String PROPERTY_SENDER_ID = "sender_id";
  private static final String PROPERTY_PASSWORD = "password";
  private static final String CACHED_KEY_FILENAME = "cache.key";
  private static final int PLAY_SERVICES_RESOLUTION_REQUEST = 9000;
  private static final String NOTIFICATION_CHANNEL_ID = "bnotify_notifications";

  private EditText senderIdEditText;
  private EditText passwordEditText;
  private TextView registrationIdTextView;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_settings);

    // Check Google Play Services.
    if (!checkPlayServices()) {
      finish();
    }

    // Initialize member variables.
    senderIdEditText = (EditText) findViewById(R.id.sender_id);
    passwordEditText = (EditText) findViewById(R.id.password);
    registrationIdTextView = (TextView) findViewById(R.id.registration_id);

    // Wire up event handlers.
    passwordEditText.addTextChangedListener(new TextWatcher() {

      @Override
      public void afterTextChanged(Editable s) {
        storePassword(s.toString());
      }

      @Override
      public void beforeTextChanged(CharSequence s, int start, int count, int after) { }

      @Override
      public void onTextChanged(CharSequence s, int start, int before, int count) { }
    });

    senderIdEditText.addTextChangedListener(new TextWatcher() {

      @Override
      public void afterTextChanged(Editable s) { storeSenderId(s.toString()); }

      @Override
      public void beforeTextChanged(CharSequence s, int start, int count, int after) { }

      @Override
      public void onTextChanged(CharSequence s, int start, int before, int count) { }
    });

    // Initialize UI content.
    senderIdEditText.setText(getSenderId());
    passwordEditText.setText(getPassword());
    registrationIdTextView.setText("Loading...");

    FirebaseInstanceId.getInstance().getInstanceId()
            .addOnCompleteListener(new OnCompleteListener<InstanceIdResult>() {
              @Override public void onComplete(Task<InstanceIdResult> task) {
                if (!task.isSuccessful()) {
                  registrationIdTextView.setText(String.format("Could not load registration ID: %s", task.getException()));
                  return;
                }
                String registrationId = task.getResult().getToken();
                storeRegistrationId(registrationId);
                registrationIdTextView.setText(registrationId);
              }
            });

    // Create a notification channel.
    NotificationChannel channel = new NotificationChannel(NOTIFICATION_CHANNEL_ID, getString(R.string.notification_channel_name), NotificationManager.IMPORTANCE_DEFAULT);
    channel.setDescription(getString(R.string.notification_channel_description));
    channel.setVibrationPattern(new long[]{0, 300, 200, 300});
    getSystemService(NotificationManager.class).createNotificationChannel(channel);
  }

  @Override
  protected void onResume() {
    super.onResume();
    checkPlayServices();
  }


  @Override
  public boolean onCreateOptionsMenu(Menu menu) {
    return true;
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
    return super.onOptionsItemSelected(item);
  }

  private String getSenderId() {
    return getGCMPreferences().getString(PROPERTY_SENDER_ID, "");
  }

  private void storeSenderId(String senderId) {
    SharedPreferences prefs = getGCMPreferences();

    if (prefs.getString(PROPERTY_SENDER_ID, "").equals(senderId)) {
      return;
    }

    prefs.edit()
      .putString(PROPERTY_SENDER_ID, senderId)
      .apply();
  }

  private void storeRegistrationId(String registrationId) {
    SharedPreferences prefs = getGCMPreferences();

    if (prefs.getString(PROPERTY_REGISTRATION_ID, "").equals(registrationId)) {
      return;
    }

    prefs.edit()
      .putString(PROPERTY_REGISTRATION_ID, registrationId)
      .apply();

    clearCachedKey();
  }

  private String getPassword() {
    return getGCMPreferences().getString(PROPERTY_PASSWORD, "");
  }

  private void storePassword(String password) {
    SharedPreferences prefs = getGCMPreferences();

    if (prefs.getString(PROPERTY_PASSWORD, "").equals(password)) {
      return;
    }

    prefs.edit()
      .putString(PROPERTY_PASSWORD, password)
      .apply();

    clearCachedKey();
  }

  private SharedPreferences getGCMPreferences() {
    return getSharedPreferences(SettingsActivity.class.getSimpleName(), Context.MODE_PRIVATE);
  }

  private boolean checkPlayServices() {
    int resultCode = GooglePlayServicesUtil.isGooglePlayServicesAvailable(this);
    if (resultCode != ConnectionResult.SUCCESS) {
      if (GooglePlayServicesUtil.isUserRecoverableError(resultCode)) {
        GooglePlayServicesUtil.getErrorDialog(resultCode, this,
            PLAY_SERVICES_RESOLUTION_REQUEST).show();
      } else {
        finish();
      }
      return false;
    }
    return true;
  }

  private void clearCachedKey() {
    File cachedKeyFile = new File(getCacheDir(), CACHED_KEY_FILENAME);
    cachedKeyFile.delete();
  }
}
