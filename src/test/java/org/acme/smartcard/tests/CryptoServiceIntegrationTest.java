package org.acme.smartcard.tests;

import org.acme.smartcard.ConfigService;
import org.acme.smartcard.CryptoService;
import org.acme.smartcard.domain.KeyStoreInfo;
import org.acme.smartcard.impl.ConfigServiceImpl;
import org.acme.smartcard.impl.CryptoServiceImpl;
import org.acme.smartcard.utils.FileIOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class CryptoServiceIntegrationTest {

    private String alias;

    private CryptoService cryptoService = CryptoServiceImpl.INSTANCE;

    private ConfigService configService = ConfigServiceImpl.INSTANCE;

    private KeyStore keyStore;

    @Before
    public void init() throws Exception {
        final String dllLocation = "D:/smartcard/src/main/resources/config/netsetpkcs11_x64.dll";
        final String keyType = "PKCS11";
        final char[] pin = {'3', '5', '1', '4'};

        final ConfigService configService = ConfigServiceImpl.INSTANCE;
        configService.loadPkcsProvider(dllLocation);
        keyStore = configService.createKeyStore(pin, keyType);

        final List<String> aliasList = new ArrayList<>();
        final List<KeyStoreInfo> infos = configService.readKeyStoreInfo(keyStore);
        for (final KeyStoreInfo info : infos) {
            final String alias = info.getAlias();
            aliasList.add(alias);
        }

        alias = aliasList.get(1);
    }

    @After
    public void tearDown() {
        configService.unLoadPkcsProvider();
    }

    @Test
    public void testEncryptDecrypt() throws Exception {
        final String text = FileIOUtils.readFileIntoString("src/test/resources/files/dummy.txt");

        // encrypting part
        final X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        final byte[] encryptedData = cryptoService.encryptData(cert, "RSA", text.getBytes(StandardCharsets.UTF_8));

        assertNotNull(encryptedData);

        FileIOUtils.writeStringIntoFile(new String(encryptedData), "target/encryptedDummyFile.txt");

        final String encryptedText = FileIOUtils.readFileIntoString("target/encryptedDummyFile.txt");

        assertNotEquals(text, encryptedText);

        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

        final byte[] decryptedData = cryptoService.decryptData(privateKey, "RSA/ECB/PKCS1Padding",
                encryptedText.getBytes());

        final String decryptedText = new String(decryptedData);

        assertEquals(text, decryptedText);
    }
}
