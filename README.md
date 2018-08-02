# JWT Sample

## Generate key
- Generate 2048 bit RSA private key
```
openssl genrsa -out private.pem 2048
```
- Convert private key to PKCS#8 format (for java can read)
```
openssl pkcs8 -top8 -inform PEM -outform DER -in private.pem -out private.der -nocrypt
```
