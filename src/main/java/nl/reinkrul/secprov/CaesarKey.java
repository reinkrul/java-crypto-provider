package nl.reinkrul.secprov;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

public class CaesarKey implements SecretKey {

    private static final int KEY_LENGTH = Integer.SIZE / 8;
    private final int shift;

    public CaesarKey(final byte[] encoded) {
        if (encoded.length != KEY_LENGTH) {
            throw new IllegalArgumentException("Invalid key length.");
        }
        this.shift = ByteBuffer.wrap(encoded).getInt();
        assertShiftValid();
    }

    public CaesarKey(final int shift) {
        this.shift = shift;
        assertShiftValid();
    }

    public String getAlgorithm() {
        return "CAESAR";
    }

    public String getFormat() {
        return "CAESAR";
    }

    public byte[] getEncoded() {
        return ByteBuffer.allocate(KEY_LENGTH).putInt(shift).array();
    }

    int getShift() {
        return shift;
    }

    private void assertShiftValid() {
        if (shift < 1) {
            throw new IllegalArgumentException("shift should be >= 1");
        }
    }
}
