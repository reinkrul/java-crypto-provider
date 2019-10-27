package nl.reinkrul.secprov;

import java.security.Provider;

public class CustomProvider extends Provider {

    public static final String NAME = "Custom";

    public CustomProvider() {
        super(NAME, "1.0", "Custom Java Security Provider");
        // Install custom keystore
        put("KeyStore.Custom", CustomKeyStore.class.getName());
        // Install Caesar cipher
        put("Cipher.Caesar", CaesarCipher.class.getName());
    }
}
