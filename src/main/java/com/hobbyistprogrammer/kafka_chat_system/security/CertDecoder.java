package com.hobbyistprogrammer.kafka_chat_system.security;

import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CertDecoder {

    public static X509Certificate readCertificate(String certFilePath)
            throws IOException, CertificateException {
        String certContent = new String(Files.readAllBytes(Paths.get(certFilePath)));

        // Extract the base64 encoded certificate data
        Pattern certPattern = Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);
        Matcher certMatcher = certPattern.matcher(certContent);
        if (!certMatcher.find()) {
            throw new CertificateException("Invalid PEM encoded certificate: No BEGIN/END markers found.");
        }
        String base64Cert = certMatcher.group(1).trim();

        byte[] certBytes = Base64.getDecoder().decode(base64Cert);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
    }

    public static PrivateKey readPrivateKey(String privateKeyFilePath)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyContent = new String(Files.readAllBytes(Paths.get(privateKeyFilePath)));

        // Extract the base64 encoded private key data
        Pattern keyPattern = Pattern.compile("-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----", Pattern.DOTALL);
        Matcher keyMatcher = keyPattern.matcher(privateKeyContent);
        if (!keyMatcher.find()) {
            throw new InvalidKeySpecException("Invalid PEM encoded private key: No BEGIN/END markers found.");
        }
        String base64Key = keyMatcher.group(1).trim();

        byte[] privateKeyBytes = Base64.getDecoder().decode(base64Key);

        KeyFactory keyFactory = KeyFactory.getInstance("EC"); // Assuming ECC private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(keySpec);
    }

    public static void main(String[] args) {
        String certFilePath = "/Users/aravindrajganesan/workspace/mylocaltests/ecc-cert-gen/ecc_certificate.pem";
        String privateKeyFilePath = "/Users/aravindrajganesan/workspace/mylocaltests/ecc-cert-gen/ecc_private_key.pem";



        try {
            X509Certificate certificate = readCertificate(certFilePath);
            PrivateKey privateKey = readPrivateKey(privateKeyFilePath);

            System.out.println("Successfully read ECC certificate:");
            System.out.println("  Subject: " + certificate.getSubjectDN());
            System.out.println("  Issuer: " + certificate.getIssuerDN());
            System.out.println("  Valid from: " + certificate.getNotBefore());
            System.out.println("  Valid until: " + certificate.getNotAfter());
            System.out.println("\nSuccessfully read ECC private key (algorithm: " + privateKey.getAlgorithm() + ")");

            // You can now use the certificate and private key for further operations
            // like establishing secure connections (e.g., using SSL/TLS with a KeyStore).

        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        } catch (CertificateException e) {
            System.err.println("Error processing certificate: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: Algorithm not supported: " + e.getMessage());
        } catch (InvalidKeySpecException e) {
            System.err.println("Error processing private key: " + e.getMessage());
        }
    }
}
