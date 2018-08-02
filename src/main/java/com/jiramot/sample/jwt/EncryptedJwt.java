package com.jiramot.sample.jwt;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

public class EncryptedJwt {


    public static void main(String[] args) {
        try {
            // Compose the JWT claims set
            Date now = new Date();
            JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                    .issuer("https://openid.net")
                    .subject("alice")
                    .audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
                    .expirationTime(new Date(now.getTime() + 1000 * 60 * 10)) // expires in 10 minutes
                    .notBeforeTime(now)
                    .issueTime(now)
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            System.out.println(jwtClaims.toJSONObject());

            // Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
            JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

            // Create the encrypted JWT object
            EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

            // Create an encrypter with the specified public RSA key
            RSAPublicKey publicKey = (RSAPublicKey) PublicKeyReader.get("keys/public.der");
            RSAEncrypter encrypter = new RSAEncrypter(publicKey);

            // Do the actual encryption
            jwt.encrypt(encrypter);

            // Serialise to JWT compact form
            String jwtString = jwt.serialize();

            System.out.println(jwtString);

            //-----------
            // Parse back
            jwt = EncryptedJWT.parse(jwtString);

            // Create a decrypter with the specified private RSA key
            PrivateKey privateKey = PrivateKeyReader.get("keys/private.der");
            RSADecrypter decrypter = new RSADecrypter(privateKey);

            // Decrypt
            jwt.decrypt(decrypter);

            System.out.println(jwt.getJWTClaimsSet());
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
