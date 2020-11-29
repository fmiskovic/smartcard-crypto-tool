package org.acme.smartcard.impl;

import org.acme.smartcard.CryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Objects;

/**
 * Singleton implementation of CryptoService
 *
 * @author Filip Miskovic
 */
public class CryptoServiceImpl implements CryptoService {

    public static final CryptoService INSTANCE = new CryptoServiceImpl();

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoServiceImpl.class);

    private CryptoServiceImpl() {

    }

    @Override
    public byte[] decryptData(PrivateKey privateKey, String transformation, byte[] base64Data) throws Exception {
        if (Objects.isNull(privateKey)) {
            throw new RuntimeException("Invalid input parameter. Parameter privateKey can not be null!");
        }

        if (Objects.isNull(base64Data)) {
            throw new RuntimeException("Invalid input parameter. Parameter base64Data can not be null!");
        }

        LOGGER.info("Start decrypting data...");
        final long startTime = System.currentTimeMillis();

        final byte[] decodedData = Base64.getDecoder().decode(base64Data);

        final Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        final byte[] decryptedData = cipher.doFinal(decodedData);

        final long totalTime = System.currentTimeMillis() - startTime;

        LOGGER.info("Decryption has finished. Time spent: [{}]", totalTime);

        return decryptedData;
    }

    @Override
    public byte[] encryptData(X509Certificate cert, String transformation, byte[] data) throws Exception {
        if (Objects.isNull(cert)) {
            throw new RuntimeException("Invalid input parameter. Parameter cert can not be null!");
        }

        if (Objects.isNull(data)) {
            throw new RuntimeException("Invalid input parameter. Parameter data can not be null!");
        }

        LOGGER.info("Start encrypting data...");
        final long startTime = System.currentTimeMillis();

        final PublicKey publicKey = cert.getPublicKey();

        final Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        final byte[] encryptedData = cipher.doFinal(data);

        final byte[] encodedData = Base64.getEncoder().encode(encryptedData);

        final long totalTime = System.currentTimeMillis() - startTime;

        LOGGER.info("Encryption has finished. Time spent: [{}}]", totalTime);

        return encodedData;
    }
}
