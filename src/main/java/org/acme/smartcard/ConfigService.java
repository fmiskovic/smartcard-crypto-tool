package org.acme.smartcard;

import org.acme.smartcard.domain.KeyStoreInfo;

import java.security.KeyStore;
import java.util.List;

public interface ConfigService {

    KeyStore createKeyStore(char[] pin, String keyType) throws Exception;

    void loadPkcsProvider(String configPath) throws Exception;

    List<KeyStoreInfo> readKeyStoreInfo(KeyStore keyStore) throws Exception;

    void unLoadPkcsProvider();
}
