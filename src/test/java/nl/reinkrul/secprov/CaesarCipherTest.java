package nl.reinkrul.secprov;

import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

import static org.junit.Assert.assertEquals;

public class CaesarCipherTest {

    @BeforeClass
    public static void setUp() throws Exception {
        Security.addProvider(new CustomProvider());
    }

    @Test
    public void test() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        final CaesarKey key = new CaesarKey(20);
        final String cipherText = encrypt(key, "Hello, World!");
        assertEquals("Byffi, Qilfx!", cipherText);
        assertEquals("Hello, World!", decrypt(key, cipherText));
    }

    private String decrypt(final CaesarKey key, final String cipherText) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
        final Cipher cipher = Cipher.getInstance("Caesar", CustomProvider.NAME);
        cipher.init(Cipher.DECRYPT_MODE, key, new SecureRandom());
        return new String(cipher.update(cipherText.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

    private String encrypt(final CaesarKey key, final String plainText) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
        final Cipher cipher = Cipher.getInstance("Caesar", CustomProvider.NAME);
        cipher.init(Cipher.ENCRYPT_MODE, key, new SecureRandom());
        return new String(cipher.update(plainText.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

    @Test
    public void testSingleCharacters() {
        // Test lowercase
        test('b', 'a', 1);
        test('c', 'a', 2);
        test('z', 'a', 25);
        test('a', 'a', 26);
        test('b', 'a', 27);

        // Test uppercase
        test('B', 'A', 1);
        test('C', 'A', 2);
        test('Z', 'A', 25);
        test('A', 'A', 26);
        test('B', 'A', 27);

        // Test other characters
        test('\n', '\n', 2);
        test('1', '1', 2);
        test('-', '-', 2);
    }

    private void test(final char cipher, final char plain, final int shift) {
        final char encrypted = CaesarCipher.encrypt(plain, shift);
        assertEquals(cipher, encrypted);
        final char decrypted = CaesarCipher.decrypt(encrypted, shift);
        assertEquals(plain, decrypted);
    }
}