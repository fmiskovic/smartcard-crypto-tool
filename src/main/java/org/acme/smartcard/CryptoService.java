package org.acme.smartcard;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Public API for encrypting and decrypting of various data formats.
 *
 * @author Filip Miskovic
 */
public interface CryptoService {

    /**
     * @param privateKey     - Private key that is used when decrypting data.
     * @param transformation - {@link Cipher} transformation (e.g. RSA/ECB/PKCS1Padding)
     * @param base64Data     - The base64 encoded data that will be decrypted.
     * @return - Decrypted byte array
     * @throws Exception
     */
    byte[] decryptData(PrivateKey privateKey, String transformation, byte[] base64Data) throws Exception;

    /**
     * @param cert           - Public certificate that is used for encrypting the data.
     * @param transformation - {@link Cipher} transformation (e.g. RSA)
     * @param data           - Raw data that will be encrypted.
     * @return - Encrypted and base64 encoded byte array.
     * @throws Exception
     */
    byte[] encryptData(X509Certificate cert, String transformation, byte[] data) throws Exception;

}
