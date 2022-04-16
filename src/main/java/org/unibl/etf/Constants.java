package org.unibl.etf;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;

public class Constants
{
    public static final int TWO_BYTES = 16;

    public static final int THREE_BYTES = 24;

    public static final int FOUR_BYTES = 32;

    public static final int KEY_LENGTH = 4096;

    public static final String PROVIDER = "BCFIPS";

    public static final String IV_KEY = "554E49424C455446424B4B52"; //UNIBLETFBKKR

    public static final String ALGORITHM = "AES/ECB/PKCS7Padding";

    public static final String KEY_ALGORITHM = "AES";

    public static final String CERT_ALGORITHM = "SHA384withRSA";

    public static final long THIRTY_DAYS = 1000L * 60 * 60 * 24 * 30;

    public static final String PATH_SEPARATOR = File.separator;

    public static final String ORIGINAL_PHOTO_PATH = "." + PATH_SEPARATOR + "Original";

    public static final String ENCODED_PHOTO_PATH = "." + PATH_SEPARATOR + "Encoded";

    public static final String PHOTO_EXTENSION = ".jpg";

    public static final String JPG = "jpg";

    public static final String BLANK = "";

    public static final String ENCODED_PHOTO_EXTENSION = ".png";

    public static final String ENCODED_PHOTO_NAME_EXTENSION = "ENC";

    public static final String QUESTION_FILE_PATH = "." + PATH_SEPARATOR + "questions.txt";

    public static final int NUM_OF_QUESTIONS = 5;

    public static final String END_PROGRAM = "2";

    public static final String LOGIN = "0";

    public static final String REGISTRATION = "1";

    public static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA1";

    public static final int ITERATION_COUNT = 10000;

    public static final int HASH_KEY_LENGTH = 128;

    public static final int SALT_LENGTH = 10;

    public static final String PASSWORD_FILE = "." + PATH_SEPARATOR + "password.txt";

    public static final String STORE_PATH = "." + PATH_SEPARATOR + "BCFKS.store";

    public static final String KEY_STORE_PASSWORD = "password";

    public static final String[] CA_CERT_ALIAS = {"interCAA", "interCAB"};

    public static final String[] CA_KEY_ALIAS = {"interCAAkey", "interCABkey"};

}