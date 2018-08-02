# JWT Sample

## Generate key
- Generate 2048 bit RSA private key
```
openssl genrsa -out private.pem 2048
```
- Convert private key to PKCS#8 format (for java can read)
```
openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private.der -nocrypt
```
- Get public key in DER format (for java can read)
```
openssl rsa -in private.pem -pubout -outform DER -out public.der
```
