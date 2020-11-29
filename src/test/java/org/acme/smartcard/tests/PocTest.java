package org.acme.smartcard.tests;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * This is a proof of concept test. It connects to a Serbian ID card and perform
 * encrypting/decrypting of some dummy text using key pair from the smart card.
 */
public class PocTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(PocTest.class);

    private Provider provider;

    private KeyStore keyStore;

    @Before
    public void setUp() throws Exception {
        final String pkcs11ConfigFile = "src/main/resources/config/pkcs11.cfg";
        //provider = new SunPKCS11();
        provider = Security.getProvider("SunPKCS11");
        provider.configure(pkcs11ConfigFile);

        Security.addProvider(provider);

        final char[] pin = {'3', '5', '1', '4'};
        keyStore = KeyStore.getInstance("PKCS11");
        keyStore.load(null, pin);
    }

    @After
    public void tearDown() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void test_case1() throws Exception {
        final List<String> aliasList = new ArrayList<>();

        final Enumeration<String> aliasesEnum = keyStore.aliases();
        while (aliasesEnum.hasMoreElements()) {
            final String alias = aliasesEnum.nextElement();
            LOGGER.info(String.format("Alias: %s", alias));
            aliasList.add(alias);

            final X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            LOGGER.info(String.format("Certificate: %s", cert));
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            LOGGER.info(String.format("Private key:  %s", privateKey));
        }

        assertEquals(2, aliasList.size());

        final String rawText = "Dummy text to encrypt and to decrypt";

        final String alias = aliasList.get(1);

        // encrypting part
        final X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        final PublicKey publicKey = cert.getPublicKey();

        final Cipher cipher = Cipher.getInstance("RSA"); //$NON-NLS-1$
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        final byte[] encryptedBytes = cipher.doFinal(rawText.getBytes(StandardCharsets.UTF_8));

        LOGGER.info(String.format("Encrypted Text: %s", new String(encryptedBytes)));
        LOGGER.info(String.format("Encrypted and Base64 encoded text: %s",
                new String(Base64.getEncoder().encode(encryptedBytes))));

        // decrypting part
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

        final Cipher cipherDecrypter = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //$NON-NLS-1$
        cipherDecrypter.init(Cipher.DECRYPT_MODE, privateKey);

        final byte[] decryptedBytes = cipherDecrypter.doFinal(encryptedBytes);

        final String decryptedText = new String(decryptedBytes);
        LOGGER.info(String.format("Decrypted Text: [%s]", decryptedText));

        assertEquals(rawText, decryptedText);
    }
}
