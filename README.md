# Encryption for AtSign 
## Description

This folder comprises of different encryption APIs and Utilities coded in Python 3.x for the Python SDK for AtSign as a part of 682 course (MS CS - UMass Boston) Project 4a

## More about the Encryption API

It makes use of the following encryption and decryption algorithms: RSA Encryption 2048 (Sign, Verify, Encrypt, Decrypt) & Keypair Generation, Base64 Encode/Decode, AES CTR 256 Encrypt/Decrypt, & Key Generation

## Table of Contents
1. Structure 
2. Usage 
3. Algorithm 
4. Collaborators

## Structure

Abstract Class : Encryption.py 

### Implementation Classes 

Format : xyz_encryption.py 

Utility : encryption_util.py 

Folder :  tests_proj_4a consists of tests for the encryption classes and for the utility

## Usage

Use the EncryptionUtil in the main SDK to get the functionality of all the algorithms.
xyz_encryption is for individual implementation of an encryption algorithm, it has to implement the abstract class encryption.py and implement the abstract methods encrypt() and decrypt().

## Algorithm/ Encryption Stack:

The utility develop should aid the development of the encryption stack like:

1. AES key and initialization vector are generated.
2. The base message is AES encrypted in the CTR mode using the keys and the initialization vector.
3. The RSA public and private keys are generated.
4. The AES key is base64 encoded.
5. The encoded AES key is RSA signed using the RSA private key and 'SHA-256'.
6. The encoded AES key is RSA encrypted using the RSA public key.
7. At the client side, the AES key is decrypted using the RSA private key.
8. The decrypted AES key is base64 decoded.
9. The AES key is also verified using the RSA public key and the Signature.
10. The message is finally obtained with AES decrypted using the AES key and initialization vector.

## Documentation of related libraries: 

[rsa](https://pypi.org/project/rsa/)

[crypto](https://pycryptodome.readthedocs.io/en/latest/src/cipher/cipher.html )

[base64](https://docs.python.org/3/library/base64.html#module-base64 )

[pycryptodome](https://www.pycryptodome.org)

[secrets](https://docs.python.org/3/library/secrets.html)

[hashlib](https://docs.python.org/3/library/hashlib.html )

[Crypto.Cipher](https://pycryptodome.readthedocs.io/en/latest/src/cipher/cipher.html)


## Collaborators: 
Muskaan Manocha

Prem Desai

Yeshaswini Murthy

## Acknowledgement

We thank our Professor - Prof. Kenneth Fletcher for giving us this opportunity to collaborate with Atsign. Special thanks to Tyler and Jeremy for motivating us and helping us to stay on track.