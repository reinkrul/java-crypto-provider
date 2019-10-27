package nl.reinkrul.secprov;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;
import java.util.stream.Collectors;

public class CustomKeyStore extends KeyStoreSpi {

    private final Properties keys = new Properties();

    public Key engineGetKey(final String alias, final char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        final String value = keys.getProperty(alias);
        if (value == null) {
            throw new UnrecoverableKeyException("Unknown key: " + alias);
        }
        try {
            return new CaesarKey(Integer.parseInt(value));
        } catch (final NumberFormatException e) {
            // Exception is ignored.
            throw new UnrecoverableKeyException("Key is invalid: " + alias);
        }
    }

    public Date engineGetCreationDate(final String alias) {
        // Not supported, so return Unix epoch
        return new Date(0);
    }

    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain) throws KeyStoreException {
        if (key instanceof CaesarKey) {
            // TODO
            keys.put(alias, String.valueOf(((CaesarKey) key).getShift()));
        } else {
            throw new KeyStoreException("Key not supported: " + key.getClass().getName());
        }
    }

    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain) throws KeyStoreException {
        // TODO
        engineSetKeyEntry(alias, new CaesarKey(key), null, chain);
    }

    public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {
        throw new KeyStoreException("Certificates are not supported.");
    }

    public void engineDeleteEntry(final String alias) throws KeyStoreException {
        keys.remove(alias);
    }

    public Enumeration<String> engineAliases() {
        return Collections.enumeration(keys.keySet().stream().map(Object::toString).collect(Collectors.toList()));
    }

    public boolean engineContainsAlias(final String alias) {
        return keys.containsKey(alias);
    }

    public int engineSize() {
        return keys.size();
    }

    public boolean engineIsKeyEntry(final String alias) {
        return keys.containsKey(alias);
    }

    public Certificate[] engineGetCertificateChain(final String alias) {
        // Certificates not supported
        return new Certificate[0];
    }

    public Certificate engineGetCertificate(final String alias) {
        // Certificates not supported
        return null;
    }

    public boolean engineIsCertificateEntry(final String alias) {
        // Certificates not supported
        return false;
    }

    public String engineGetCertificateAlias(final Certificate cert) {
        // Certificates not supported
        return null;
    }

    public void engineStore(final OutputStream stream, final char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        keys.store(stream, null);
    }

    public void engineLoad(final InputStream stream, final char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (stream != null) {
            keys.load(stream);
        }
    }
}
