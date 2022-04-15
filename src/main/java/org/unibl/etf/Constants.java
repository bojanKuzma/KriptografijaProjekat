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

    public static final SecretKey SampleAesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");

    public static final SecretKey SampleTripleDesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617"), "TripleDES");

    public static final SecretKey SampleHMacKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f10111213"), "HmacSHA512");

    public static final byte[] SampleInput = Strings.toByteArray("Hello World!");

    public static final byte[] SampleTwoBlockInput = Strings.toByteArray("Some cipher modes require more than one block");

    public static final byte[] Nonce = Strings.toByteArray("number only used once");

    public static final byte[] PersonalizationString = Strings.toByteArray("a constant personal marker");

    public static final byte[] Initiator = Strings.toByteArray("Initiator");

    public static final byte[] Recipient = Strings.toByteArray("Recipient");

    public static final byte[] UKM = Strings.toByteArray("User keying material");
}