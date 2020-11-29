package org.acme.smartcard;

import org.acme.smartcard.domain.KeyStoreInfo;
import org.acme.smartcard.impl.ConfigServiceImpl;
import org.acme.smartcard.impl.CryptoServiceImpl;
import org.acme.smartcard.utils.FileIOUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class Main {

    public static void main(String[] args) throws Exception {
        final String cfgLocation = "src/main/resources/config/pkcs11.cfg";
        final String keyType = "PKCS11";
        final char[] pin = {'3', '5', '1', '4'};

        // initializing personal ID as java KeyStore
        final ConfigService configService = ConfigServiceImpl.INSTANCE;
        configService.loadPkcsProvider(cfgLocation);
        KeyStore keyStore = configService.createKeyStore(pin, keyType);

        // getting right alias from java KeyStore
        final List<String> aliasList = new ArrayList<>();
        final List<KeyStoreInfo> infos = configService.readKeyStoreInfo(keyStore);
        for (final KeyStoreInfo info : infos) {
            final String alias = info.getAlias();
            aliasList.add(alias);
        }

        String alias = aliasList.get(1);

        // with cryptoService perform encryption and decryption
        CryptoService cryptoService = CryptoServiceImpl.INSTANCE;

        final String text = FileIOUtils.readFileIntoString("src/main/resources/files/dummy.txt");

        // encrypting part of the code
        final X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        final byte[] encryptedData = cryptoService.encryptData(cert, "RSA", text.getBytes(StandardCharsets.UTF_8));

        // save encrypted file
        FileIOUtils.writeStringIntoFile(new String(encryptedData, StandardCharsets.UTF_8), "target/encryptedDummyFile.txt");

        // decrypting part of the code
        final String encryptedText = FileIOUtils.readFileIntoString("target/encryptedDummyFile.txt");

        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

        final byte[] decryptedData = cryptoService.decryptData(privateKey, "RSA/ECB/PKCS1Padding",
                encryptedText.getBytes());

        final String decryptedText = new String(decryptedData, StandardCharsets.UTF_8);

        // save decrypted data into the file
        FileIOUtils.writeStringIntoFile(decryptedText, "target/deryptedDummyFile.txt");

        // unload personal ID card
        configService.unLoadPkcsProvider();
        System.exit(0);
    }
}
