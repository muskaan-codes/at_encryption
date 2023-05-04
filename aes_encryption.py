"""
-*- coding: utf-8 -*-
Implementation class of the AES Encryption and decryption operations.
Created: April 2023
Owners: Project 4a: Muskaan Manocha, Prem Desai, Yeshaswini Murthy
"""

# pip install cryptography
# pip install pycryptodome

import secrets
import base64
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from encryption import Encryption
from cryptography.hazmat.primitives import padding


class AesEncryption(Encryption):

    def __init__(self):
        self.iv = b'\x00' * 16

    def encrypt(self, plain_text, key, nonce):
        """
        Encrypts the given plain_text using AES in CTR mode with a 256-bit key and returns
        the result as a Base64-encoded string.

        :param plain_text: The plain_text to encrypt (it should be base64encoded).
        :type plain_text: bytes
        :param key: The encryption key.
        :type key: bytes
        :param nonce: The nonce value.
        :type nonce: bytes
        :return: The Base64-encoded ciphertext.
        :rtype: bytes
        """
        # Add padding to the plain_text
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plain_text = padder.update(plain_text) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_plain_text) + encryptor.finalize()
        return base64.b64encode(cipher_text).decode('utf-8')

    def decrypt(self, ciphertext, key, nonce):
        """
        Decrypts the given ciphertext using AES in CTR mode with a 256-bit key and returns
        the result as a bytes object.

        :param ciphertext: The Base64-encoded ciphertext to decrypt.
        :type ciphertext: str
        :param key: The encryption key.
        :type key: bytes
        :param nonce: The nonce value.
        :type nonce: bytes
        :return: The plain_text.
        :rtype: bytes
        """
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
        # Remove padding from the decrypted plain_text
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_plain_text = unpadder.update(decrypted) + unpadder.finalize()
        return unpadded_plain_text

    # def encrypt(self, clear_text):
    #     """
    #     Encrypts the given plaintext using AES in CBC mode with PKCS7 padding and returns
    #     the result as a Base64-encoded string.

    #     :param clear_text: The plaintext to encrypt.
    #     :type clear_text: str
    #     :param key_base64: The Base64-encoded encryption key.
    #     :type key_base64: str
    #     :return: The Base64-encoded ciphertext.
    #     :rtype: str
    #     """
    #     cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
    #     padded_text = clear_text.encode() + (AES.block_size - len(clear_text.encode()) % AES.block_size) * chr(AES.block_size - len(clear_text.encode()) % AES.block_size).encode()
    #     encrypted = cipher.encrypt(padded_text)
    #     return base64.b64encode(encrypted).decode()

    # def decrypt(self, encrypted_text):
    #     """
    #     Converts the given string to a Base64-decoded string.

    #     :param my_string: The string to decode.
    #     :type my_string: str
    #     :return: The Base64-decoded string.
    #     :rtype: str
    #     """
    #     cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
    #     decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
    #     return decrypted[:-decrypted[-1]].decode()


# # Example usage of AesEncryption class (CBC), uncomment everything below and run this file for demo output

# aes = AesEncryption()
# key = secrets.token_bytes(32)
# iv = b'\x00' * 16
# plaintext = 'This is a sample plaintext to encrypt using AES CTR mode.'
# plaintext = plaintext.encode()
# nonce = secrets.token_bytes(16)
# ciphertext = aes.encrypt(plaintext, key, nonce)
# print("Encrypted : " + ciphertext) 
# print("iv = " + str(len(iv)))
# decrypted = aes.decrypt(ciphertext, key, nonce)
# print("Decrypted : " + decrypted.decode('utf-8'))
# padder = padding.PKCS7(algorithms.AES.block_size).unpadder()
# dycryptedtext = padder.update(decrypted) + padder.finalize()
# dycryptedtext = dycryptedtext.decode('utf-8')
# print(decrypted == plaintext)

# # Example usage of AesEncryption class (CTR) --> MAIN, uncomment everything below and run this file for demo output

# aes = AesEncryption()
# aes_key = secrets.token_bytes(32)
# iv = b'\x00' * 16
# plain_text = 'This is a sample plaintext to encrypt using AES CTR mode.'
# nonce = secrets.token_bytes(16)
# plain_text = plain_text.encode()
# cipher_text = aes.encrypt(plain_text, aes_key, nonce)
# print("Encrypted %s to :%s " % (plain_text, cipher_text)) 
# decrypted = aes.decrypt(cipher_text, aes_key, nonce)
# print(decrypted == plain_text)
# print(decrypted.decode('utf-8') == plain_text.decode('utf-8'))

""" Sample OP:
    Encrypted b'This is a sample plaintext to encrypt using AES CTR mode.' to :vfGNYptPKqyqE19IcNof+jCankh6Iyvd2sYGueZ8jdxf/AVUs5CxV4UXpUYbEzA9NAPovA9BfIKErbvfueDPhQ== 
    True
    True
"""