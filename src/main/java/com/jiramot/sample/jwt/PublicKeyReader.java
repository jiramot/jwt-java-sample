package com.jiramot.sample.jwt;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyReader {
    public static PublicKey get(String filename)
            throws Exception {
        ClassLoader classLoader = new EncryptedJwt().getClass().getClassLoader();
        byte[] keyBytes = Files.readAllBytes(Paths.get(classLoader.getResource(filename).toURI()));

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
