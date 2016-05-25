package cc.bran.bnotify;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.gcm.GoogleCloudMessaging;

import java.io.File;
import java.io.IOException;

public class SettingsActivity extends Activity {

  private static final String PROPERTY_REGISTRATION_ID = "registration_id";
  private static final String PROPERTY_SENDER_ID = "sender_id";
  private static final String PROPERTY_PASSWORD = "password";
  private static final String CACHED_KEY_FILENAME = "cache.key";
  private static final int PLAY_SERVICES_RESOLUTION_REQUEST = 9000;

  private GoogleCloudMessaging gcm;
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
    gcm = GoogleCloudMessaging.getInstance(this);
    senderIdEditText = (EditText) findViewById(R.id.sender_id);
    passwordEditText = (EditText) findViewById(R.id.password);
    registrationIdTextView = (TextView) findViewById(R.id.registration_id);
    Button registerButton = (Button) findViewById(R.id.register);

    // Wire up event handlers.
    registerButton.setOnClickListener(new View.OnClickListener() {

      @Override
      public void onClick(View view) {
        registerInBackground();
      }
    });

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
    registrationIdTextView.setText(getRegistrationId());
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

  private void registerInBackground() {
    AsyncTask<Void, Void, String> task = new AsyncTask<Void, Void, String>() {

      @Override
      protected void onPreExecute() {
        registrationIdTextView.setText("Registering...");
      }

      @Override
      protected String doInBackground(Void... params) {
        try {
          String registrationId = gcm.register(getSenderId());
          storeRegistrationId(registrationId);
          return registrationId;
        } catch (IOException exception) {
          return String.format("Error: %s", exception.getMessage());
        }
      }

      @Override
      protected void onPostExecute(String message) {
        registrationIdTextView.setText(message);
      }
    };

    task.execute();
  }

  private String getSenderId() {
    SharedPreferences prefs = getGCMPreferences();
    return prefs.getString(PROPERTY_SENDER_ID, null);
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

  private String getRegistrationId() {
    SharedPreferences prefs = getGCMPreferences();
    return prefs.getString(PROPERTY_REGISTRATION_ID, null);
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
    SharedPreferences prefs = getGCMPreferences();
    return prefs.getString(PROPERTY_PASSWORD, "");
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
