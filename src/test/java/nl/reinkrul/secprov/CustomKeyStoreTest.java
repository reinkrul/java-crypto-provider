package nl.reinkrul.secprov;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertEquals;

public class CustomKeyStoreTest {

    private static final String KEY = "key1";
    private static final int KEY_SHIFT = 20;

    @Before
    public void setUp() throws Exception {
        Security.addProvider(new CustomProvider());
    }

    @Test
    public void testCreateSaveLoad() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        final KeyStore expected = KeyStore.getInstance("Custom");
        expected.load(null, null);
        expected.setKeyEntry(KEY, new CaesarKey(KEY_SHIFT), null, null);
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        expected.store(outputStream, null);

        final KeyStore actual = KeyStore.getInstance("Custom");
        actual.load(new ByteArrayInputStream(outputStream.toByteArray()), null);
        assertEquals(KEY_SHIFT, ((CaesarKey) actual.getKey(KEY, null)).getShift());
    }
}