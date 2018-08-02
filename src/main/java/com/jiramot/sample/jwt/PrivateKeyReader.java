package com.jiramot.sample.jwt;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class PrivateKeyReader {
    public static PrivateKey get(String filename)
            throws Exception {
        ClassLoader classLoader = new EncryptedJwt().getClass().getClassLoader();
        byte[] keyBytes = Files.readAllBytes(Paths.get(classLoader.getResource(filename).toURI()));

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
}
