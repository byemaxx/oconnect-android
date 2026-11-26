/*
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

package app.openconnect.fragments;

import java.io.File;

import android.Manifest.permission;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.view.View;

import app.openconnect.PreferenceScreenStyler;
import app.openconnect.R;
import app.openconnect.core.DeviceStateReceiver;

public class AdvancedGeneralSettings extends PreferenceFragment {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.advanced_general_settings);

        Preference loadTun = findPreference("loadTunModule");
        if (Build.VERSION.SDK_INT >= 26) {
            loadTun.setEnabled(true);
            loadTun.setTitle(R.string.ensure_tun_title);
            loadTun.setSummary(R.string.ensure_tun_summary);
        } else if (new File("/system/lib/modules/tun.ko").length() <= 10) {
            loadTun.setEnabled(false);
            loadTun.setSummary(R.string.root_tun_module_unavailable);
        }

        findPreference("trace_log").setOnPreferenceChangeListener((preference, newValue) -> {
            Intent intent = new Intent(DeviceStateReceiver.PREF_CHANGED);
            intent.setPackage(getActivity().getPackageName());
            getActivity().sendBroadcast(intent, permission.ACCESS_NETWORK_STATE);
            return true;
        });
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        PreferenceScreenStyler.apply(this);
    }
}
