package app.openconnect;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class CredentialStore {
    static final String PREFIX = "oc1:";
    private static final String ALIAS = "openconnect-vpn-password-v1";
    private static final int IV_SIZE = 12;

    private CredentialStore() {}

    private static synchronized SecretKey key(boolean create)
            throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(ALIAS)) return (SecretKey) store.getKey(ALIAS, null);
        if (!create) throw new GeneralSecurityException("Password key unavailable");
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build());
        return generator.generateKey();
    }

    static String seal(String value, String field) throws GeneralSecurityException, IOException {
        if (value.isEmpty()) return "";
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key(true));
        cipher.updateAAD(field.getBytes(StandardCharsets.UTF_8));
        byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        byte[] iv = cipher.getIV();
        if (iv.length != IV_SIZE) throw new GeneralSecurityException("Unexpected password IV size");
        byte[] blob = Arrays.copyOf(iv, iv.length + encrypted.length);
        System.arraycopy(encrypted, 0, blob, iv.length, encrypted.length);
        return PREFIX + Base64.encodeToString(blob, Base64.NO_WRAP);
    }

    static String open(String value, String field) throws GeneralSecurityException, IOException {
        byte[] blob = Base64.decode(value.substring(PREFIX.length()), Base64.NO_WRAP);
        if (blob.length <= IV_SIZE + 16) throw new GeneralSecurityException("Invalid saved password");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(false), new GCMParameterSpec(128, blob, 0, IV_SIZE));
        cipher.updateAAD(field.getBytes(StandardCharsets.UTF_8));
        return new String(cipher.doFinal(blob, IV_SIZE, blob.length - IV_SIZE), StandardCharsets.UTF_8);
    }
}
