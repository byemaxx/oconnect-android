/*
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

package app.openconnect.fragments;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import android.Manifest.permission;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.widget.Toast;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Build;
import android.preference.ListPreference;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.view.View;

import app.openconnect.PreferenceScreenStyler;
import app.openconnect.R;
import app.openconnect.core.CrossSimDiagnostics;
import app.openconnect.core.DeviceStateReceiver;
import app.openconnect.core.RootAccess;

public class AdvancedGeneralSettings extends PreferenceFragment
        implements SharedPreferences.OnSharedPreferenceChangeListener {

    private boolean rootCheckRunning;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.advanced_general_settings);

        Preference loadTun = findPreference("loadTunModule");
        if (loadTun != null) {
            // Modern kernels may have built-in TUN; a missing tun.ko is not a failure.
            if (Build.VERSION.SDK_INT >= 26) {
                loadTun.setEnabled(true);
                loadTun.setTitle(R.string.ensure_tun_title);
                loadTun.setSummary(R.string.ensure_tun_summary);
            } else if (!isTunModuleAvailable()) {
                loadTun.setEnabled(false);
                loadTun.setSummary(R.string.root_tun_module_unavailable);
            }
        }

        ListPreference connectionMode = (ListPreference) findPreference("connection_mode");
        Preference targets = findPreference("root_epdg_targets");
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

        Preference crossSim = findPreference("cross_sim_diagnostics");
        crossSim.setOnPreferenceClickListener(preference -> {
            readCrossSimDiagnostics(preference);
            return true;
        });

        Preference traceLog = findPreference("trace_log");
        if (traceLog != null) {
            traceLog.setOnPreferenceChangeListener((preference, newValue) -> {
                Intent intent = new Intent(DeviceStateReceiver.PREF_CHANGED);
                intent.setPackage(getActivity().getPackageName());
                getActivity().sendBroadcast(intent, permission.ACCESS_NETWORK_STATE);
                return true;
            });
        }

        SharedPreferences preferences = getPreferenceScreen().getSharedPreferences();
        for (Map.Entry<String, ?> entry : preferences.getAll().entrySet()) {
            onSharedPreferenceChanged(preferences, entry.getKey());
        }
        onSharedPreferenceChanged(preferences, "timestamp_format");
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        PreferenceScreenStyler.apply(this);
    }

    @Override
    public void onResume() {
        super.onResume();
        getPreferenceScreen().getSharedPreferences()
                .registerOnSharedPreferenceChangeListener(this);
    }

    @Override
    public void onPause() {
        getPreferenceScreen().getSharedPreferences()
                .unregisterOnSharedPreferenceChangeListener(this);
        super.onPause();
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences preferences, String key) {
        Preference preference = findPreference(key);
        if (preference instanceof ListPreference) {
            ListPreference listPreference = (ListPreference) preference;
            String value = preferences.getString(key, "");
            if (!value.isEmpty()) {
                listPreference.setValue(value);
            }
            preference.setSummary(listPreference.getEntry());
        }
    }

    private void readCrossSimDiagnostics(Preference preference) {
        Activity activity = getActivity();
        if (activity == null) return;
        Context context = activity.getApplicationContext();
        preference.setEnabled(false);
        preference.setSummary(R.string.cross_sim_reading);
        new Thread(() -> {
            Map<String, String> fields = null;
            try {
                fields = CrossSimDiagnostics.read(context);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException ignored) {
                // Shell output can contain unrelated system details. Keep it out of the UI.
            }
            final Map<String, String> result = fields;
            activity.runOnUiThread(() -> {
                preference.setEnabled(true);
                preference.setSummary(R.string.cross_sim_diagnostics_summary);
                if (!isAdded() || getActivity() != activity || activity.isFinishing()) return;
                if (result == null) {
                    Toast.makeText(activity, R.string.cross_sim_read_failed, Toast.LENGTH_LONG).show();
                    return;
                }
                chooseCrossSimTarget(activity, result);
            });
        }, "CrossSimDiagnostics").start();
    }

    private void chooseCrossSimTarget(Activity activity, Map<String, String> fields) {
        List<String> subscriptions = new ArrayList<>();
        List<String> labels = new ArrayList<>();
        for (String key : fields.keySet()) {
            if (key.startsWith("slot.")) {
                String id = key.substring("slot.".length());
                subscriptions.add(id);
                labels.add(subscriptionLabel(fields, id));
            }
        }
        if (subscriptions.isEmpty()) {
            Toast.makeText(activity, R.string.cross_sim_no_subscriptions, Toast.LENGTH_LONG).show();
            return;
        }
        new AlertDialog.Builder(activity)
                .setTitle(R.string.cross_sim_target)
                .setItems(labels.toArray(new String[0]), (dialog, which) ->
                        showCrossSimSnapshot(activity, fields, subscriptions.get(which)))
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private String subscriptionLabel(Map<String, String> fields, String id) {
        if (!id.matches("[0-9]+")) return getString(R.string.cross_sim_unknown);
        return getString(R.string.cross_sim_subscription, fields.getOrDefault("slot." + id,
                getString(R.string.cross_sim_unknown)), id);
    }

    private void showCrossSimSnapshot(Activity activity, Map<String, String> fields, String id) {
        String unknown = getString(R.string.cross_sim_unknown);
        String active = fields.getOrDefault("active", unknown);
        String message = getString(R.string.cross_sim_snapshot,
                subscriptionLabel(fields, id),
                subscriptionLabel(fields, fields.getOrDefault("default", unknown)),
                subscriptionLabel(fields, active),
                fields.getOrDefault("roaming." + active, unknown),
                fields.getOrDefault("dataRoamingEnabled", unknown),
                fields.getOrDefault("enabled." + id, unknown),
                fields.getOrDefault("eligible." + id, unknown),
                fields.getOrDefault("registered." + id, unknown),
                fields.getOrDefault("tech." + id, unknown),
                fields.getOrDefault("voice." + id, unknown),
                fields.getOrDefault("preferred." + id, unknown), unknown);
        new AlertDialog.Builder(activity)
                .setTitle(R.string.cross_sim_diagnostics_title)
                .setMessage(message)
                .setPositiveButton(android.R.string.ok, null)
                .show();
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

    private boolean isTunModuleAvailable() {
        return new File("/system/lib/modules/tun.ko").length() > 10;
    }
}
