package org.unibl.etf;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.*;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static org.unibl.etf.Constants.*;


public class HashPassword {
    public static boolean hash(String password, boolean isRegistered, String username) throws GeneralSecurityException,
            IOException, OperatorCreationException {
        byte[] salt = new byte[SALT_LENGTH];
        List<String> lines = Files.readAllLines(Paths.get(PASSWORD_FILE));
        SecretKeyFactory factoryBC = SecretKeyFactory.getInstance(HASH_ALGORITHM, PROVIDER);
        if (!isRegistered) {
            for (String line : lines) {
                if (line.contains(username))
                    return false;//unsuccessful login attempt because username is already taken
            }
            SecureRandom rnd = new SecureRandom();
            rnd.nextBytes(salt);

            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, HASH_KEY_LENGTH);
            SecretKey keyBC = factoryBC.generateSecret(keySpec);

            SecretKey secretKey = AES.defineKey(Constants.IV_KEY.getBytes()); //for AES encryption
            String fullHash = Arrays.toString(AES.ecbEncrypt(secretKey, salt)) + '#'
                    + Hex.toHexString(keyBC.getEncoded()) + '#' + username + "#0\n";
            Files.writeString(Paths.get(PASSWORD_FILE), fullHash, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return true; //successful registration
        } else {
            boolean flag = false;
            List<String> newLines = new LinkedList<>();
            for (String line : lines) {
                if (line.contains(username)) {
                    String fileHash = line.split("#")[1];
                    String fileSalt = line.split("#")[0];
                    int login_num = Integer.parseInt(line.split("#")[3]);
                    byte[] encodedSalt = string2ByteArray(fileSalt);
                    SecretKey secretKey = AES.defineKey(Constants.IV_KEY.getBytes());
                    salt = AES.ecbDecrypt(secretKey, encodedSalt);
                    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, HASH_KEY_LENGTH);
                    SecretKey keyBC = factoryBC.generateSecret(keySpec);
                    if (Hex.toHexString(keyBC.getEncoded()).equals(fileHash)) {
                        flag = true;//successful login attempt
                        login_num++;
                        line = line.replaceFirst("[0-9]$", login_num + "");
                        if (login_num > 3) {
                            KeyStore keyStore = KeyStoreBC.getStore(KEY_STORE_PASSWORD.toCharArray());
                            X509Certificate cert = (X509Certificate) keyStore.getCertificate(username);
                            if (cert.getIssuerX500Principal().getName().contains("Intermediate CA A")) {
                                X509Certificate caCert = (X509Certificate) keyStore.getCertificate(CA_CERT_ALIAS[0]);
                                PrivateKey caKey = (PrivateKey)
                                        keyStore.getKey(CA_KEY_ALIAS[0], KEY_STORE_PASSWORD.toCharArray());
                                genCRL(caCert, caKey, cert, 0);
                            } else {
                                X509Certificate caCert = (X509Certificate) keyStore.getCertificate(CA_CERT_ALIAS[1]);
                                PrivateKey caKey = (PrivateKey)
                                        keyStore.getKey(CA_KEY_ALIAS[1], KEY_STORE_PASSWORD.toCharArray());
                                genCRL(caCert, caKey, cert, 1);
                            }
                        }
                    }
                }
                newLines.add(line);
            }
            Files.write(Paths.get(PASSWORD_FILE), newLines, StandardOpenOption.WRITE);
            return flag;
        }
    }

    private static byte[] string2ByteArray(String salt) {
        salt = salt.replaceAll("[\\[\\]]", "");
        String[] byteArray = salt.split(", ");
        byte[] bytes = new byte[byteArray.length];
        for (int i = 0; i < byteArray.length; i++) {
            bytes[i] = Byte.parseByte(byteArray[i]);
        }
        return bytes;
    }

    public static boolean login(KeyStore keyStore, String username) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException,
            CRLException {
        boolean flag;
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(username);
        cert.checkValidity(); //date validation
        if (cert.getIssuerX500Principal().getName().contains("Intermediate CA A")) {
            cert.verify(keyStore.getCertificate(CA_CERT_ALIAS[0]).getPublicKey());
            flag = checkCRL(cert, 0);
        } else {
            cert.verify(keyStore.getCertificate(CA_CERT_ALIAS[1]).getPublicKey());
            flag = checkCRL(cert, 1);
        }
        return flag;
    }

    private static boolean checkCRL(X509Certificate cert, int index) throws CertificateException, CRLException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        try {
            FileInputStream is = new FileInputStream("./crl" + index + ".crl");
            X509CRL crl = (X509CRL) fact.generateCRL(is);
            is.close();
            return crl.isRevoked(cert);
        } catch (IOException e) {
            return false;
        }
    }

    private static void genCRL(X509Certificate rootCACert, PrivateKey rootCAPrivateKey,
                               X509Certificate revokedCert, int index)
            throws GeneralSecurityException, OperatorCreationException, IOException {

        X509CRL crl = Certificate.makeV2Crl(rootCACert, rootCAPrivateKey, revokedCert, index);
        FileOutputStream fileOutputStream = new FileOutputStream("./crl" + index + ".crl");
        fileOutputStream.write(crl.getEncoded());
        fileOutputStream.flush();
        fileOutputStream.close();
    }
}
