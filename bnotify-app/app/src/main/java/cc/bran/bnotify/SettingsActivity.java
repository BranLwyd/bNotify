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

import java.io.IOException;
import java.util.Objects;

public class SettingsActivity extends Activity {

    private static final String PROPERTY_REGISTRATION_ID = "registration_id";
    private static final String PROPERTY_SENDER_ID = "sender_id";
    private static final String PROPERTY_APP_VERSION = "app_version";
    private static final String PROPERTY_PASSWORD = "password";
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
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {}
        });

        // Initialize UI content.
        SharedPreferences prefs = getGCMPreferences();
        String senderId = prefs.getString(PROPERTY_SENDER_ID, null);
        senderIdEditText.setText(senderId == null ? "" : senderId);
        passwordEditText.setText(getPassword());

        String registrationId = getRegistrationId(getApplicationContext());
        registrationIdTextView.setText(registrationId == null ? "" : registrationId);
    }

    @Override
    protected void onResume() {
        super.onResume();
        checkPlayServices();
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.settings, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void registerInBackground() {
        final String senderId = senderIdEditText.getText().toString();

        AsyncTask<Void, Void, String> task = new AsyncTask<Void, Void, String>() {

            @Override
            protected void onPreExecute() {
                registrationIdTextView.setText("Registering...");
            }

            @Override
            protected String doInBackground(Void... params) {
                try {
                    String registrationId = gcm.register(senderId);
                    storeRegistrationId(getApplicationContext(), senderId, registrationId);
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

    private String getRegistrationId(Context context) {
        SharedPreferences prefs = getGCMPreferences();
        String registrationId = prefs.getString(PROPERTY_REGISTRATION_ID, null);
        if (registrationId == null) {
            return null;
        }

        // Check if app was updated or sender ID changed.
        int registeredVersion = prefs.getInt(PROPERTY_APP_VERSION, Integer.MIN_VALUE);
        int currentVersion = getAppVersion(context);
        if (registeredVersion != currentVersion) {
            return null;
        }

        String registeredSenderId = prefs.getString(PROPERTY_SENDER_ID, null);
        String currentSenderId = senderIdEditText.getText().toString();
        if (!Objects.equals(registeredSenderId, currentSenderId)) {
            return null;
        }

        return registrationId;
    }

    private void storeRegistrationId(Context context, String senderId, String registrationId) {
        SharedPreferences prefs = getGCMPreferences();
        int appVersion = getAppVersion(context);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(PROPERTY_REGISTRATION_ID, registrationId);
        editor.putString(PROPERTY_SENDER_ID, senderId);
        editor.putInt(PROPERTY_APP_VERSION, appVersion);
        editor.commit();
    }

    private String getPassword() {
        SharedPreferences prefs = getGCMPreferences();
        return prefs.getString(PROPERTY_PASSWORD, "");
    }

    private void storePassword(String password) {
        SharedPreferences prefs = getGCMPreferences();

        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(PROPERTY_PASSWORD, password);
        editor.commit();
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

    private static int getAppVersion(Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return packageInfo.versionCode;
        } catch (PackageManager.NameNotFoundException exception) {
            throw new RuntimeException("Could not get package name", exception);
        }
    }
}
