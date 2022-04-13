package org.unibl.etf;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;
import java.util.HashMap;

public class Main {
    private static final boolean DEV_ENV = false;
    private static final String PATH_SEPARATOR = File.separator;
    private static final String ORIGINAL_PHOTO_PATH = "." + PATH_SEPARATOR + "Original";
    private static final String ENCODED_PHOTO_PATH = "." + PATH_SEPARATOR + "Encoded";
    private static final String PHOTO_EXTENSION = ".jpg";
    private static final String JPG = "jpg";
    private static final String BLANK = "";
    private static final String ENCODED_PHOTO_EXTENSION = ".png";
    private static final String ENCODED_PHOTO_NAME_EXTENSION = "ENC";
    private static final String QUESTION_FILE_PATH = "." + PATH_SEPARATOR + "questions.txt";

    private static final int NUM_OF_QUESTIONS = 5;

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        //this line is needed for loading bouncy castle
        Security.addProvider(new BouncyCastleFipsProvider());
        Steganography steganography = new Steganography();
        SecretKey secretKey = AES.defineKey(ExValues.IV_KEY.getBytes());

        if (DEV_ENV) {
            //first start up, when there are no images in encrypted folder (Encoded)
            try {
//                String[] questions = Files.readAllLines(
//                        Paths.get(QUESTION_FILE_PATH), StandardCharsets.UTF_8
//                ).toArray(new String[0]);//zero for just faster converting to array
//
//                File folder = new File(ORIGINAL_PHOTO_PATH);
//                String[] files = folder.list();
//                for (int i = 0; i < questions.length; i++) {
//                    byte[] encoded = AES.ecbEncrypt(secretKey, questions[i].getBytes());
//                    String newFileName = files[i].replace(PHOTO_EXTENSION, BLANK) + ENCODED_PHOTO_NAME_EXTENSION;
//
//                    steganography.encode(
//                            ORIGINAL_PHOTO_PATH, files[i].replace(PHOTO_EXTENSION, BLANK), JPG, newFileName, encoded
//                    );
//
//                    Files.move(
//                            Paths.get(ORIGINAL_PHOTO_PATH + PATH_SEPARATOR + newFileName + ENCODED_PHOTO_EXTENSION),
//                            Paths.get(ENCODED_PHOTO_PATH + PATH_SEPARATOR + newFileName + ENCODED_PHOTO_EXTENSION),
//                            StandardCopyOption.REPLACE_EXISTING
//                    );
//                }

                generateKeyPair();
            } catch (Exception e) {
                e.getStackTrace();
            }


            //  byte[] encoded = AES.ecbEncrypt(secretKey, "Test".getBytes());
            //  steganography.encode(ORIGINAL_PHOTO_PATH,"1","jpg","405",encoded);
        } else {
            System.out.println("Dobrodošli na kviz");
            System.out.println("Izaberite jednu od opcija: [0] Prijava [1] Registracija [3] Zatvori aplikaciju");
            BufferedReader standardInput = new BufferedReader(new InputStreamReader(System.in));
            //todo dok god ne upise jedan od brojeva citaj ulaz
            //todo login
            ////todo kod logina vrsiti provjere validnosti certifikata, broj logovanja, provjera potpisa
            //todo ovo dole je za dekodovanje kad covjek uloguje
            File folder = new File(ENCODED_PHOTO_PATH);
            HashMap<Integer,String> selectedQuestions = new HashMap<>();
            String[] files = folder.list();
            if (files != null) {

                //select 5 questions to be displayed to logged-in user and load in and decode them
                for (int i = 0; i < NUM_OF_QUESTIONS;) {
                    Integer key = Utils.getRandomNumber(files.length);
                    if (!selectedQuestions.containsKey(key)){
                        byte[] decoded = steganography.decode(ENCODED_PHOTO_PATH, files[key]
                                .replace(ENCODED_PHOTO_EXTENSION, BLANK));
                        selectedQuestions.put(key,new String(AES.ecbDecrypt(secretKey, decoded), StandardCharsets.UTF_8));
                        System.out.println(new String(AES.ecbDecrypt(secretKey, decoded), StandardCharsets.UTF_8));
                        i++;
                    }
                }
            } else throw new NullPointerException("There are no images in Encoded folder!");

            //todo registracija
            standardInput.close();
            System.out.println("Kraj");
        }

        //KeyPair keyPair = generateKeyPair();
        //X509Certificate x509Certificate = makeV1Certificate(keyPair.getPrivate(),keyPair.getPublic());
        //System.out.println(writeCertificate(x509Certificate));
    }


    //KeyPair keyPair = generateKeyPair(); todo generisanje para kljuceva
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BCFIPS");
        keyPair.initialize(new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4));
        return keyPair.generateKeyPair();
    }


    //todo generisanje root CA
    public static X509Certificate makeV1Certificate(PrivateKey caSignerKey, PublicKey caPublicKey)
            throws GeneralSecurityException, OperatorCreationException {

        X509v1CertificateBuilder v1CertBldr = new JcaX509v1CertificateBuilder(
                new X500Name("CN=Issuer CA"),
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() - 1000L * 5),
                new Date(System.currentTimeMillis() + ExValues.THIRTY_DAYS),
                new X500Name("CN=Issuer CA"), caPublicKey);

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA384withRSA").setProvider("BCFIPS");

        return new JcaX509CertificateConverter().setProvider("BCFIPS")
                .getCertificate(v1CertBldr.build(signerBuilder.build(caSignerKey)));
    }

    public static String writeCertificate(X509Certificate certificate) throws IOException {
        StringWriter sWrt = new StringWriter();
        PEMEncryptor encryptor =
                new JcePEMEncryptorBuilder("AES-256-CBC").build("test".toCharArray());
        JcaMiscPEMGenerator gen = new JcaMiscPEMGenerator(certificate, encryptor);//mozda ne treba i ne radi?
        JcaPEMWriter pemWriter = new JcaPEMWriter(sWrt);
        pemWriter.writeObject(gen);
        pemWriter.close();
        return sWrt.toString();
    }
}
