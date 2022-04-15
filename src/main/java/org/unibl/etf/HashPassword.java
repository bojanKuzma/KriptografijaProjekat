package org.unibl.etf;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.List;

import static org.unibl.etf.Constants.*;


public class HashPassword {
    public static boolean hash(String password, boolean isRegistered, String username) throws GeneralSecurityException, IOException {
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
                    + Hex.toHexString(keyBC.getEncoded()) + '#' + username;
            Files.writeString(Paths.get(PASSWORD_FILE), fullHash, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return true; //successful registration
        } else {

            for (String line : lines) {
                if (line.contains(username)) {
                    String fileHash = line.split("#")[1];
                    String fileSalt = line.split("#")[0];
                    byte[] encodedSalt = string2ByteArray(fileSalt);
                    SecretKey secretKey = AES.defineKey(Constants.IV_KEY.getBytes());
                    salt = AES.ecbDecrypt(secretKey, encodedSalt);
                    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, HASH_KEY_LENGTH);
                    SecretKey keyBC = factoryBC.generateSecret(keySpec);
                    if (Hex.toHexString(keyBC.getEncoded()).equals(fileHash))
                        return true;//successful login attempt
                }
            }
        }
        return false; //unsuccessful login attempt
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
}
