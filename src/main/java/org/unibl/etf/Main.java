package org.unibl.etf;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import static org.unibl.etf.Constants.*;

public class Main {
    private static final boolean DEV_ENV = false;

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        //this line is needed for loading bouncy castle
        Security.addProvider(new BouncyCastleFipsProvider());
        Steganography steganography = new Steganography();
        SecretKey secretKey = AES.defineKey(Constants.IV_KEY.getBytes());

        if (DEV_ENV) {
            //first start up, when there are no images in encrypted folder (Encoded)
            try {
               /* String[] questions = Files.readAllLines(
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
                }*/

                /*KeyPair rootCAKeyPair = Certificate.generateKeyPair();
                X509Certificate rootCACert = Certificate.makeV1Certificate(rootCAKeyPair.getPrivate(), rootCAKeyPair.getPublic());
                Certificate.saveToFile(rootCACert, "./RootCA.cer");
                //System.out.println(writeCertificate(x509Certificate));
                //todo enkriptuj ga prije

                //todo kreiraj dva intermediate CA tijela
                //todo enkriptuj ih prije

                X509Certificate interCACertA = Certificate.makeV3Certificate(rootCACert,rootCAKeyPair.getPrivate(), Certificate.generateKeyPair().getPublic());
                Certificate.saveToFile(interCACertA, "./IntermediateCAA.cer");*/

            } catch (Exception e) {
                e.getStackTrace();
            }
        } else {
            System.out.println("Dobrodošli na kviz");
            System.out.println("Izaberite jednu od opcija: [0] Prijava [1] Registracija [2] Zatvori aplikaciju");
            BufferedReader standardInput = new BufferedReader(new InputStreamReader(System.in));
            String input = standardInput.readLine();
            while (!input.equals(END_PROGRAM)) {
                //todo dok god ne upise jedan od brojeva citaj ulaz


                if(input.equals(LOGIN)) {
                    //todo login
                    ////todo kod logina vrsiti provjere validnosti certifikata, broj logovanja
                    //todo ovo dole je za dekodovanje kad covjek uloguje i biranje pitanja
                    System.out.print("Username: ");
                    String username = standardInput.readLine();
                    System.out.println();
                    System.out.print("Password: ");
                    String password = standardInput.readLine();
                    System.out.println();
                    if(HashPassword.hash(password,true,username )) {
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
                        } else throw new NullPointerException("There are no images in Encoded folder!");
                        input = END_PROGRAM;
                    }
                    else{
                        System.out.println("Neispravni kredencijali za pristup sistemu");
                    }
                }
                else if(input.equals(REGISTRATION)){
                    //todo registracija
                    System.out.print("Username: ");
                    String username = standardInput.readLine();
                    System.out.println();
                    System.out.print("Password: ");
                    String password = standardInput.readLine();
                    System.out.println();
                    if(HashPassword.hash(password,false, username)) {
                        //todo kreiraj user certifikat
                        System.out.println();
                    }
                    System.out.println("Korisnicko ime je vec zauzeto");
                }
                else {
                    System.out.println("Nepostojeća komanda");
                }
                System.out.println("Izaberite jednu od opcija: [0] Prijava [1] Registracija [2] Zatvori aplikaciju");
                input = standardInput.readLine();
            }
            standardInput.close();
            System.out.println("Kraj");
        }

    }
}
