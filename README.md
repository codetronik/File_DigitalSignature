# File_DigitalSignature
![image](https://raw.githubusercontent.com/codetronik/File_DigitalSignature/master/screenshots/main.png)

Built in Visual Studio 2019 + Based on openssl

This program generates and validates digital signatures of files.

## Design
### Signing
![image](https://raw.githubusercontent.com/codetronik/File_DigitalSignature/master/screenshots/sign.png)
### Verification
![image](https://raw.githubusercontent.com/codetronik/File_DigitalSignature/master/screenshots/verification.png)

## Features
- Generate a Digital signature of the file 
- Verify a Digital signature of the file 

## How To Use
1. Press "Generate Key Pair" button to generate rsa keypairs.

The key files are created in the running directory. (PrivateKey.pem and PublicKey.pem)

2. Press "Sign" button to sign the file.

The Signature file is created in the running directory. (file name.sig)

3. Press "Verify" button to verify the file.
