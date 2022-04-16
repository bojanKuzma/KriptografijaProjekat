package org.unibl.etf;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

import static org.unibl.etf.Constants.*;

public class Certificate {


    //method for generating key pair
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", PROVIDER);
        keyPair.initialize(new RSAKeyGenParameterSpec(KEY_LENGTH, RSAKeyGenParameterSpec.F4));
        return keyPair.generateKeyPair();
    }


    //todo generisanje root CA
    public static X509Certificate makeV1Certificate(PrivateKey caPrivateKey, PublicKey caPublicKey)
            throws GeneralSecurityException, OperatorCreationException {
        //X500Name name = new X500Name("O=Evil Inc,CN=original,L=Banja Luka,C=CA"); ne koristi se cisto test

        X509v1CertificateBuilder v1CertBldr = new JcaX509v1CertificateBuilder(
                new X500Name("CN=Root CA"),
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() - 1000L * 5),
                new Date(System.currentTimeMillis() + Constants.THIRTY_DAYS),
                new X500Name("CN=Root CA"), caPublicKey);

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(CERT_ALGORITHM).setProvider(PROVIDER);

        return new JcaX509CertificateConverter().setProvider(PROVIDER)
                .getCertificate(v1CertBldr.build(signerBuilder.build(caPrivateKey)));
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

    public static void saveToFile(X509Certificate certificate, String filePath) throws IOException,
            CertificateEncodingException {
        FileOutputStream fileOutputStream = new FileOutputStream(filePath);
        fileOutputStream.write(certificate.getEncoded());
        fileOutputStream.flush();
        fileOutputStream.close();
    }


    public static X509CRL makeV2Crl(X509Certificate caCert, PrivateKey caPrivateKey,
                                    X509Certificate revokedCertificate, int index)
            throws GeneralSecurityException, CertIOException, OperatorCreationException {
        Date now = new Date();

        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(), now);
        crlGen.setNextUpdate(new Date(System.currentTimeMillis() + Constants.THIRTY_DAYS));

        // this is the actual certificate we are revoking
        crlGen.addCRLEntry(revokedCertificate.getSerialNumber(), now, CRLReason.cessationOfOperation);
        X509CRL crlOld = null;
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream("./crl" + index + ".crl");
            crlOld = (X509CRL) fact.generateCRL(is);
            is.close();
        } catch(IOException ignored){

        }
        if (crlOld != null)
            for(var e : crlOld.getRevokedCertificates()) {
                crlGen.addCRLEntry(e.getSerialNumber(), e.getRevocationDate(), CRLReason.cessationOfOperation);
            }

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        crlGen.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        X509CRLHolder crl = crlGen.build(new JcaContentSignerBuilder(CERT_ALGORITHM).setProvider(PROVIDER)
                .build(caPrivateKey));
        return new JcaX509CRLConverter().setProvider(PROVIDER).getCRL(crl);
    }


    public static X509Certificate makeV3Certificate(X509Certificate caCertificate, PrivateKey caPrivateKey,
                                                    PublicKey eePublicKey, String commonName)
            throws GeneralSecurityException, CertIOException, OperatorCreationException {
        X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
                caCertificate.getSubjectX500Principal(), // issuer
                BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(10)), // serial number
                new Date(System.currentTimeMillis() - 1000L * 5), // start time
                new Date(System.currentTimeMillis() + Constants.THIRTY_DAYS), // expiry time
                new X500Principal("CN=" + commonName), // subject
                eePublicKey); // subject public key

        //
        // extensions
        //
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        v3CertBldr.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(eePublicKey));

        v3CertBldr.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(caCertificate));

        v3CertBldr.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));

        v3CertBldr.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature
                | KeyUsage.cRLSign | KeyUsage.keyCertSign));

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(CERT_ALGORITHM).setProvider(PROVIDER);
        return new JcaX509CertificateConverter().setProvider(PROVIDER)
                .getCertificate(v3CertBldr.build(signerBuilder.build(caPrivateKey)));
    }

    public static X509Certificate createEndCert(X509Certificate caCertificate, PrivateKey caPrivateKey,
                                                PublicKey eePublicKey, String commonName, String email)
            throws GeneralSecurityException, CertIOException, OperatorCreationException {
        X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
                caCertificate.getSubjectX500Principal(), // issuer
                BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(10)), // serial number
                new Date(System.currentTimeMillis() - 1000L * 5), // start time
                new Date(System.currentTimeMillis() + Constants.THIRTY_DAYS), // expiry time
                new X500Principal("CN=" + commonName), // subject
                eePublicKey); // subject public key

        //
        // extensions
        //
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        v3CertBldr.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(eePublicKey));

        v3CertBldr.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(caCertificate));

        v3CertBldr.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

        v3CertBldr.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(CERT_ALGORITHM).setProvider(PROVIDER);
        return new JcaX509CertificateConverter().setProvider(PROVIDER)
                .getCertificate(v3CertBldr.build(signerBuilder.build(caPrivateKey)));
    }

}
