package nl.reinkrul.secprov;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CaesarKeyTest {

    @Test
    public void testEncoding() {
        assertEquals(20, new CaesarKey(new CaesarKey(20).getEncoded()).getShift());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNegativeShift() {
        new CaesarKey(-1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testZeroShift() {
        new CaesarKey(0);
    }
}