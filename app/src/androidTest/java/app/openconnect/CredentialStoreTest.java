package app.openconnect;


import org.junit.Test;

import java.security.GeneralSecurityException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class CredentialStoreTest {
    @Test
    public void encryptsPasswordsAndBindsThemToTheProfileField() throws Exception {
        String value = "test-value-only";
        String field = "test-profile:test-field";
        String sealed = CredentialStore.seal(value, field);
        assertTrue(sealed.startsWith(CredentialStore.PREFIX));
        assertFalse(sealed.contains(value));
        assertEquals(value, CredentialStore.open(sealed, field));
        try {
            CredentialStore.open(sealed, "different-test-profile:test-field");
            fail("Accepted a password from a different profile");
        } catch (GeneralSecurityException expected) {
            // Authentication must reject ciphertext associated with a different field.
        }
    }
}
