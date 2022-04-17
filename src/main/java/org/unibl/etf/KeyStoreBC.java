package org.unibl.etf;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.unibl.etf.Constants.*;

public class KeyStoreBC {
    public static void createKeyStoreWithCA(char[] storePassword, X509Certificate[] CAcerts, PrivateKey[] privateKeys)
            throws KeyStoreException, NoSuchProviderException, CertificateException, IOException,
            NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");
        keyStore.load(null, null);
        keyStore.setCertificateEntry("rootCA", CAcerts[0]);
        keyStore.setCertificateEntry("interCAA", CAcerts[1]);
        keyStore.setCertificateEntry("interCAB", CAcerts[2]);
        keyStore.setKeyEntry("rootCAkey", privateKeys[0], storePassword, new Certificate[]{CAcerts[0]});
        keyStore.setKeyEntry("interCAAkey", privateKeys[1], storePassword, new Certificate[]{CAcerts[1],
                CAcerts[0]});
        keyStore.setKeyEntry("interCABkey", privateKeys[2], storePassword, new Certificate[]{CAcerts[2],
                CAcerts[0]});
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        keyStore.store(byteArrayOutputStream, storePassword);
        Files.write(Path.of(STORE_PATH), byteArrayOutputStream.toByteArray());
    }

    public static KeyStore getStore() throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");
        keyStore.load(new FileInputStream(STORE_PATH), KEY_STORE_PASSWORD.toCharArray());
        return keyStore;
    }


    public static void storeCertificate(X509Certificate trustedCert, String alias)
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");
        keyStore.load(new FileInputStream(STORE_PATH), KEY_STORE_PASSWORD.toCharArray());
        keyStore.setCertificateEntry(alias, trustedCert);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        keyStore.store(byteArrayOutputStream, KEY_STORE_PASSWORD.toCharArray());
        Files.write(Path.of(STORE_PATH), byteArrayOutputStream.toByteArray());
    }

}
