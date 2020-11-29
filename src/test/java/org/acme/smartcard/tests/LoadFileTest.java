package org.acme.smartcard.tests;

import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertNotNull;

public class LoadFileTest {

    @Test
    public void testLoadFile() throws IOException {
        ClassLoader classloader = Thread.currentThread().getContextClassLoader();
        try (InputStream in = classloader.getResourceAsStream("config/pkcs11.cfg")) {
            assertNotNull(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
