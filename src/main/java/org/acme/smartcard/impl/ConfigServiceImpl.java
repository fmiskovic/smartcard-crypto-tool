package org.acme.smartcard.impl;

import org.acme.smartcard.ConfigService;
import org.acme.smartcard.domain.KeyStoreInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

/**
 * Singleton implementation of ConfigService
 *
 * @author Filip Miskovic
 */
public class ConfigServiceImpl implements ConfigService {

    public static final ConfigServiceImpl INSTANCE = new ConfigServiceImpl();

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigServiceImpl.class);

    private String providerName;

    private ConfigServiceImpl() {

    }

    @Override
    public KeyStore createKeyStore(char[] pin, String keyType) throws Exception {
        LOGGER.info("Creating keystore of keyType {} ", keyType);
        final KeyStore keyStore = KeyStore.getInstance(keyType);
        keyStore.load(null, pin);
        return keyStore;
    }

    @Override
    public void loadPkcsProvider(String configPath) {
        final String config = "name = SmartCard\n" + "library = " + configPath;
        LOGGER.info("Loading provider with config: {}", config);

        //final Provider provider = new SunPKCS11();
        final Provider provider = Security.getProvider("SunPKCS11");
        Provider configuredProvider = provider.configure(config);
        Security.addProvider(configuredProvider);

        this.providerName = provider.getName();
    }

    @Override
    public List<KeyStoreInfo> readKeyStoreInfo(KeyStore keyStore) throws Exception {
        final List<KeyStoreInfo> infos = new ArrayList<>();

        if (Objects.nonNull(keyStore)) {
            final Enumeration<String> aliasesEnum = keyStore.aliases();
            while (aliasesEnum.hasMoreElements()) {
                final KeyStoreInfo info = new KeyStoreInfo();

                final String alias = aliasesEnum.nextElement();
                info.setAlias(alias);
                LOGGER.info("Alias: {}", alias);

                final X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                info.setCert(cert);
                LOGGER.info("Certificate: {}", cert);

                final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
                info.setPrivateKey(privateKey);
                LOGGER.info("Private key: {}", privateKey);

                final PublicKey publicKey = cert.getPublicKey();
                info.setPublicKey(publicKey);
                LOGGER.info("Public key: {}", publicKey);

                infos.add(info);
            }
        }

        return infos;
    }

    @Override
    public void unLoadPkcsProvider() {
        LOGGER.info("Unloading provider: {}", providerName);
        Security.removeProvider(providerName);
        this.providerName = null;
    }
}
