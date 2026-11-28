/*
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

package app.openconnect.fragments;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.widget.Toast;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.preference.ListPreference;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.view.View;

import app.openconnect.PreferenceScreenStyler;
import app.openconnect.R;
import app.openconnect.core.EpdgDiscovery;
import app.openconnect.core.RootAccess;
import app.openconnect.core.WifiCallingRestart;

public class CallingSettings extends PreferenceFragment {

    private boolean rootCheckRunning;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.calling_settings);

        ListPreference connectionMode = (ListPreference) findPreference("connection_mode");
        Preference targets = findPreference("root_epdg_targets");
        ListPreference targetSim = (ListPreference) findPreference("epdg_target_slot");
        android.telephony.TelephonyManager tm = (android.telephony.TelephonyManager)
                getActivity().getSystemService(Context.TELEPHONY_SERVICE);
        List<String> simLabels = new ArrayList<>(), simValues = new ArrayList<>();
        simLabels.add(getString(R.string.epdg_automatic));
        simValues.add("auto");
        int count = tm == null ? 1 : tm.getPhoneCount();
        for (int slot = 0; slot < count; slot++) {
            simLabels.add(getString(R.string.epdg_sim_slot, slot + 1));
            simValues.add(Integer.toString(slot));
        }
        targetSim.setEntries(simLabels.toArray(new String[0]));
        targetSim.setEntryValues(simValues.toArray(new String[0]));
        Preference rootCheck = findPreference("root_epdg_check");
        if (connectionMode != null) {
            SharedPreferences prefs = getPreferenceScreen().getSharedPreferences();
            boolean voWifi = prefs.getBoolean("root_epdg_enabled", false);
            connectionMode.setValue(voWifi ? "vowifi" : "global");
            if (targets != null) targets.setEnabled(voWifi);
            connectionMode.setOnPreferenceChangeListener((preference, newValue) -> {
                boolean enableVoWifi = "vowifi".equals(newValue);
                prefs.edit().putBoolean("root_epdg_enabled", enableVoWifi).apply();
                if (targets != null) targets.setEnabled(enableVoWifi);
                if (enableVoWifi) checkRootAccess();
                Toast.makeText(getActivity(), R.string.connection_mode_reconnect, Toast.LENGTH_SHORT).show();
                return true;
            });
        }
        if (rootCheck != null) {
            rootCheck.setOnPreferenceClickListener(preference -> {
                checkRootAccess();
                return true;
            });
        }

        Preference restart = findPreference("wifi_calling_restart");
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            restart.setEnabled(false);
            restart.setSummary(R.string.wfc_restart_unsupported);
        }
        restart.setOnPreferenceClickListener(preference -> {
            new AlertDialog.Builder(getActivity())
                    .setTitle(R.string.wfc_restart_title)
                    .setMessage(R.string.wfc_restart_confirm)
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(android.R.string.ok, (dialog, which) -> restartCalling(preference))
                    .show();
            return true;
        });
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        PreferenceScreenStyler.apply(this);
    }

    private void restartCalling(Preference preference) {
        Activity activity = getActivity();
        if (activity == null) return;
        Context context = activity.getApplicationContext();
        String slot = getPreferenceScreen().getSharedPreferences().getString(EpdgDiscovery.TARGET_SIM, "auto");
        preference.setEnabled(false);
        preference.setSummary(R.string.wfc_restart_running);
        new Thread(() -> {
            String message;
            try {
                message = WifiCallingRestart.request(context, slot);
            } catch (IOException e) {
                message = context.getString(R.string.wfc_restart_failed) + " " + e.getMessage();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                message = context.getString(R.string.wfc_restart_timeout);
            }
            String result = message;
            activity.runOnUiThread(() -> {
                preference.setEnabled(true);
                if (!isAdded() || getActivity() != activity) return;
                preference.setSummary(result);
            });
        }, "WifiCallingRestart").start();
    }

    private void checkRootAccess() {
        Activity activity = getActivity();
        if (activity == null || rootCheckRunning) return;
        Context context = activity.getApplicationContext();
        Preference status = findPreference("root_epdg_check");
        rootCheckRunning = true;
        if (status != null) status.setSummary(R.string.root_check_running);
        new Thread(() -> {
            String result;
            try {
                RootAccess.check(context);
                result = context.getString(R.string.root_check_success);
            } catch (Exception e) {
                result = context.getString(R.string.root_check_failed, e.getMessage());
            }
            final String message = result;
            activity.runOnUiThread(() -> {
                rootCheckRunning = false;
                if (!isAdded() || getActivity() != activity) return;
                Preference current = findPreference("root_epdg_check");
                if (current != null) current.setSummary(message);
                Toast.makeText(activity, message, Toast.LENGTH_LONG).show();
            });
        }, "RootAccessCheck").start();
    }

}
