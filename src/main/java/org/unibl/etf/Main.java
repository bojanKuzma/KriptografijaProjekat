package org.unibl.etf;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.OperatorCreationException;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.*;
import java.util.HashMap;
import static org.unibl.etf.Constants.*;

public class Main {
    //select the run method dev is for creating all the needed resources and for testing
    private static final boolean DEV_ENV = false;

    public static void main(String[] args) throws GeneralSecurityException, IOException, OperatorCreationException {
        //this line is needed for loading bouncy castle
        Security.addProvider(new BouncyCastleFipsProvider());
        Steganography steganography = new Steganography();
        SecretKey secretKey = AES.defineKey(Constants.IV_KEY.getBytes());

        if (DEV_ENV) {
            //first start up, when there are no images in encrypted folder (Encoded)
            try {
                String[] questions = Files.readAllLines(
                        Paths.get(QUESTION_FILE_PATH), StandardCharsets.UTF_8
                ).toArray(new String[0]);//zero for just faster converting to array

                File folder = new File(ORIGINAL_PHOTO_PATH);
                String[] files = folder.list();
                for (int i = 0; i < questions.length; i++) {
                    byte[] encoded = AES.ecbEncrypt(secretKey, questions[i].getBytes());
                    String newFileName = files[i].replace(PHOTO_EXTENSION, BLANK) + ENCODED_PHOTO_NAME_EXTENSION;

                    steganography.encode(
                            ORIGINAL_PHOTO_PATH, files[i].replace(PHOTO_EXTENSION, BLANK), JPG, newFileName, encoded
                    );

                    Files.move(
                            Paths.get(ORIGINAL_PHOTO_PATH + PATH_SEPARATOR + newFileName + ENCODED_PHOTO_EXTENSION),
                            Paths.get(ENCODED_PHOTO_PATH + PATH_SEPARATOR + newFileName + ENCODED_PHOTO_EXTENSION),
                            StandardCopyOption.REPLACE_EXISTING
                    );
                }
                //generating ROOT CA
                KeyPair rootCAKeyPair = Certificate.generateKeyPair();
                X509Certificate rootCACert = Certificate.makeV1Certificate(rootCAKeyPair.getPrivate(),
                        rootCAKeyPair.getPublic());

                KeyPair interCAAkeyPair = Certificate.generateKeyPair();
                KeyPair interCABkeyPair = Certificate.generateKeyPair();

                //generating intermediate CA's
                X509Certificate interCACertA = Certificate.makeV3Certificate(rootCACert,rootCAKeyPair.getPrivate(),
                        interCAAkeyPair.getPublic(), "Intermediate CA A");

                X509Certificate interCACertB = Certificate.makeV3Certificate(rootCACert,rootCAKeyPair.getPrivate(),
                        interCABkeyPair.getPublic(), "Intermediate CA B");


                KeyStoreBC.createKeyStoreWithCA(
                        KEY_STORE_PASSWORD.toCharArray(),
                        new X509Certificate[]{rootCACert,interCACertA,interCACertB},
                        new PrivateKey[]{rootCAKeyPair.getPrivate(),interCAAkeyPair.getPrivate(),interCABkeyPair.getPrivate()}
                        );

                /*  this is for saving CA's on file system
                Certificate.saveToFile(interCACertA, "./Intermediate CA A.cer");

                Certificate.saveToFile(interCACertB, "./Intermediate CA B.cer");

                Certificate.saveToFile(rootCACert,"./rootCA.cer");
                */
            } catch (Exception e) {
                e.getStackTrace();
            }
        } else {
            System.out.println("Dobrodošli na kviz");
            System.out.println("Izaberite jednu od opcija: [0] Prijava [1] Registracija [2] Zatvori aplikaciju");
            BufferedReader standardInput = new BufferedReader(new InputStreamReader(System.in));
            String input = standardInput.readLine();
            while (!input.equals(END_PROGRAM)) {
                if(input.equals(LOGIN)) {
                    System.out.println("PRIJAVA");
                    System.out.print("Username: ");
                    String username = standardInput.readLine();
                    System.out.print("Password: ");
                    String password = standardInput.readLine();
                    if(HashPassword.hash(password,true,username )) {
                        KeyStore keyStore = KeyStoreBC.getStore(KEY_STORE_PASSWORD.toCharArray());
                        try {
                            //cert.checkValidity();

                            if(HashPassword.login(keyStore,username))
                            {
                                throw new CRLException();
                            }
                            File folder = new File(ENCODED_PHOTO_PATH);
                            HashMap<Integer, String> selectedQuestions = new HashMap<>();
                            String[] files = folder.list();
                            if (files != null) {

                                //select 5 questions to be displayed to logged-in user and load in and decode them
                                for (int i = 0; i < NUM_OF_QUESTIONS; ) {
                                    Integer key = Utils.getRandomNumber(files.length);
                                    if (!selectedQuestions.containsKey(key)) {
                                        byte[] decoded = steganography.decode(ENCODED_PHOTO_PATH, files[key]
                                                .replace(ENCODED_PHOTO_EXTENSION, BLANK));
                                        selectedQuestions.put(key, new String(AES.ecbDecrypt(secretKey, decoded), StandardCharsets.UTF_8));
                                        System.out.println(new String(AES.ecbDecrypt(secretKey, decoded), StandardCharsets.UTF_8));
                                        i++;
                                    }
                                }
                                //todo mjeri vrijeme
                                //todo ucitaj rezultate
                                //todo dekoduj rezultate
                                //todo ubaci novi i srotiraj
                                //todo enkoduj i sacuvaj fajl na fajl sistem
                            } else throw new NullPointerException("There are no images in Encoded folder!");
                        }catch (CertificateExpiredException | CRLException e){
                            System.out.println("Certifakt je istekao");
                        }
                    }
                    else{
                        System.out.println("Neispravni kredencijali za pristup sistemu");
                    }
                }
                else if(input.equals(REGISTRATION)){
                    System.out.println("REGISTRACIJA");
                    System.out.print("Username: ");
                    String username = standardInput.readLine();
                    System.out.print("Password: ");
                    String password = standardInput.readLine();
                    if(HashPassword.hash(password,false, username)) {
                        KeyStore keyStore = KeyStoreBC.getStore(KEY_STORE_PASSWORD.toCharArray());
                        int index =(int)Math.round(Math.random());
                        KeyPair endEntityKeyPair = Certificate.generateKeyPair();

                        PrivateKey CAPrivateKey = (PrivateKey) keyStore.getKey(
                                CA_KEY_ALIAS[index],
                                KEY_STORE_PASSWORD.toCharArray()
                        );
                        X509Certificate CACert = (X509Certificate) keyStore.getCertificate(CA_CERT_ALIAS[index]);

                        X509Certificate endEntityCert = Certificate.createEndCert(
                                CACert,
                                CAPrivateKey,
                                endEntityKeyPair.getPublic(),
                                username,
                                "");
                        KeyStoreBC.storeCertificate(endEntityCert,username);
                        Certificate.saveToFile(endEntityCert, "./" + username + ".cer");

                        System.out.println();
                        System.out.println("Uspješno kreiran novi nalog");
                    }
                    else System.out.println("Korisnicko ime je vec zauzeto");
                }
                else {
                    System.out.println("Nepostojeća komanda");
                }
                System.out.println("Izaberite jednu od opcija: [0] Prijava [1] Registracija [2] Zatvori aplikaciju");
                input = standardInput.readLine();
            }
            standardInput.close();
        }
        System.out.println("Kraj");
    }
}
