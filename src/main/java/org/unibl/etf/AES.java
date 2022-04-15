package org.unibl.etf;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import static org.unibl.etf.Constants.*;

public class AES {

    public static SecretKey defineKey(byte[] keyBytes)
    {
        if (keyBytes.length != TWO_BYTES && keyBytes.length != THREE_BYTES && keyBytes.length != FOUR_BYTES)
        {
            throw new IllegalArgumentException("keyBytes wrong length for AES key");
        }
        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }

    public static byte[] ecbEncrypt(SecretKey key, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }


    public static byte[] ecbDecrypt(SecretKey key, byte[] cipherText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }
}
