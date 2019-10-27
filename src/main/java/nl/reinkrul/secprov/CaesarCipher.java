package nl.reinkrul.secprov;

import javax.crypto.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.BiFunction;

public class CaesarCipher extends CipherSpi {

    private static final Charset CHARSET = StandardCharsets.UTF_8;
    private CaesarKey key;
    private StringBuilder output;
    private BiFunction<Character, Integer, Character> func;

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return inputLen;
    }

    @Override
    protected byte[] engineGetIV() {
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(final int opmode, final Key key, final SecureRandom random) throws InvalidKeyException {
        assertModeSupported(opmode);
        setKey(key);
        if (opmode == Cipher.ENCRYPT_MODE) {
            this.func = CaesarCipher::encrypt;
        } else {
            this.func = CaesarCipher::decrypt;
        }
        output = new StringBuilder();
    }

    static char decrypt(final char character, final int shift) {
        final Character base = findBase(character);
        if (base == null) {
            return character;
        }
        final int val = character - base - shift % 26;
        if (val < 0) {
            return (char)(26 + val + base);
        } else {
            return (char)(val + base);
        }

    }

    static char encrypt(final char character, final int shift) {
        final Character base = findBase(character);
        return base == null ? character : (char) ((character - base + shift) % 26 + base);
    }

    private static Character findBase(final char character) {
        if (character >= 'a' && character <= 'z') {
            return 'a';
        } else if (character >= 'A' && character <= 'Z') {
            return 'A';
        } else {
            return null;
        }
    }

    @Override
    protected void engineInit(final int opmode, final Key key, final AlgorithmParameterSpec params, final SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(final int opmode, final Key key, final AlgorithmParameters params, final SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected byte[] engineUpdate(final byte[] input, final int inputOffset, final int inputLen) {
        final String str = new String(input, inputOffset, inputLen, CHARSET);
        for (int i = 0; i < str.length(); i++) {
            output.append(func.apply(str.charAt(i), key.getShift()));
        }
        return output.toString().getBytes(CHARSET);
    }

    @Override
    protected int engineUpdate(final byte[] input, final int inputOffset, final int inputLen, final byte[] output, final int outputOffset) throws ShortBufferException {
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        return new byte[0];
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected void engineSetPadding(final String padding) throws NoSuchPaddingException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineSetMode(final String mode) throws NoSuchAlgorithmException {
        throw new UnsupportedOperationException();
    }

    private void setKey(final Key key) {
        if (key instanceof CaesarKey) {
            this.key = (CaesarKey) key;
        } else {
            throw new IllegalArgumentException("Expected a " + CaesarKey.class.getSimpleName() + " but got " + key.getClass().getName());
        }
    }

    private void assertModeSupported(final int opmode) {
        if (opmode != Cipher.DECRYPT_MODE && opmode != Cipher.ENCRYPT_MODE) {
            throw new UnsupportedOperationException("Unsupported mode: " + opmode);
        }
    }
}
