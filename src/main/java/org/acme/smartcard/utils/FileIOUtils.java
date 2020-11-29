package org.acme.smartcard.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;

public class FileIOUtils {

    public static String readFileIntoString(String filePath) throws IOException {
        return Files.readString(Paths.get(filePath), StandardCharsets.UTF_8);
    }

    public static void writeStringIntoFile(String message, String filePath) {
        if (Objects.isNull(message)) {
            return;
        }

        try (OutputStream out = new FileOutputStream(new File(filePath))) {
            out.write(message.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
