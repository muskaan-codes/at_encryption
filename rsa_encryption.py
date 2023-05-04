"""
-*- coding: utf-8 -*-
Implementation of the RSA Encryption and Decryption functionality
Created: April 2023
Owners: Project 4a: Muskaan Manocha, Prem Desai, Yeshaswini Murthy
"""
    
import rsa
import base64
from cryptography.hazmat.primitives import serialization
from encryption import Encryption

class RsaEncryption(Encryption):

    def generate_key_pair(self, b=2048):
        """
        Generate a pair of public and private keys for RSA encryption.
        
        Returns:
            A tuple containing the public key and the private key.
        """
        (public_key, private_key) = rsa.newkeys(b)
        return (public_key, private_key)

    def encrypt(self, message, public_key):
        """
        Encrypt a message using RSA encryption with a public key.
        
        Args:
            message (str): The message to be encrypted.
            public_key (rsa.PublicKey): The public key to be used for encryption.
        
        Returns:
            The encrypted message as a Base64-encoded string.
        """
        encoded_message = message.encode()
        encrypted_message = rsa.encrypt(encoded_message, public_key)
        return base64.b64encode(encrypted_message)

    def decrypt(self, encrypted_message, private_key):
        """
        Decrypt a message using RSA encryption with a private key.
        
        Args:
            encrypted_message (str): The encrypted message as a Base64-encoded string.
            private_key (rsa.PrivateKey): The private key to be used for decryption.
        
        Returns:
            The decrypted message as a string.
        """
        decoded_message = base64.b64decode(encrypted_message)
        decrypted_message = rsa.decrypt(decoded_message, private_key)
        return decrypted_message.decode()

    def sign(self, message, private_key, sign='SHA-256'):
        """
        Sign a message using RSA encryption with a private key.
        
        Args:
            message (str): The message to be signed.
            private_key (rsa.PrivateKey): The private key to be used for signing.
            sign (str): default rsa sign used is SHA-256
        
        Returns:
            The signature as a Base64-encoded string.
        """
        encoded_message = message.encode()
        signature = rsa.sign(encoded_message, private_key, sign)
        return base64.b64encode(signature).decode()

    def verify(self, message, signature, public_key):
        """
        Verify a message's signature using RSA encryption with a public key.
        
        Args:
            message (str): The message whose signature is to be verified.
            signature (str): The signature to be verified as a Base64-encoded string.
            public_key (rsa.PublicKey): The public key to be used for verification.
        
        Returns:
            True if the signature is valid, False otherwise.
        """
        encoded_message = message.encode()
        decoded_signature = base64.b64decode(signature)
        try:
            rsa.verify(encoded_message, decoded_signature, public_key)
            return True
        except:
            return False
    
# Example usage of RsaEncryption class, uncomment everything below and run this file for demo output
   
# rsa_encryption = RsaEncryption()

# (public_key, private_key) = rsa_encryption.generate_key_pair()

# message = "Hello, world!"
# encrypted_message = rsa_encryption.encrypt(message, public_key)

# decrypted_message = rsa_encryption.decrypt(encrypted_message, private_key)

# signature = rsa_encryption.sign(message, private_key)

# is_valid_signature = rsa_encryption.verify(message, signature, public_key)

# print("Public Key:", public_key)
# print("Private Key:", private_key)
# print("Original Message:", message)
# print("Encrypted Message:", encrypted_message)
# print("Decrypted Message:", decrypted_message)
# print("Is message equal to decrypted message? %s" % (message == decrypted_message))
# print("Signature:", signature)
# print("Is Valid Signature?", is_valid_signature)

"""Example OP: 
    /Users/muskaanmanocha/workspace/682/atPlatform_Python_Client_SDK/main/api/proj_4a/rsa_encryption.py 
    Public Key: PublicKey(17349529302504048428245104689596750787977594276025703823407057754630827498564816475789695767587995268061458694208031541217632930911563912795730499995889630400349227891052566471590441570585387620331720096976684439510680673160288691559348920005670536655170546358873115399605580642843894237229773141785087968298155863429246580540044339953371697850671318213864492928521966494159402911899274905935970618207913162006953822677009300153234327424570672467698402022494681506712944198959731021934900941872598868747852600568029558692504224825082470980626578885427157844435243630881971005393433379289010007767406702539967287201501, 65537)
    Private Key: PrivateKey(17349529302504048428245104689596750787977594276025703823407057754630827498564816475789695767587995268061458694208031541217632930911563912795730499995889630400349227891052566471590441570585387620331720096976684439510680673160288691559348920005670536655170546358873115399605580642843894237229773141785087968298155863429246580540044339953371697850671318213864492928521966494159402911899274905935970618207913162006953822677009300153234327424570672467698402022494681506712944198959731021934900941872598868747852600568029558692504224825082470980626578885427157844435243630881971005393433379289010007767406702539967287201501, 65537, 9265506898204704136420322323815345187897154274087914213638815042069044394002907924571453558533039876438516476147536566254438753405019102916681683626899874330717350140940839930202259105093131615905674708854295365715150579987031817211303724616605410423592308506043289118912909081885595897019460565509855873259357879142718953333401544402194202046060943453594598138059037200903887227697681473366447747008493069192776090596408791510137924114756991470501216880319291214018142707462160509824555475069981341042659533133374014827127596561890657958462202174162719032865245097441346521939970747350258752708739650954985373973, 2219225161675843561054796989921664979718321678979224713656700229977563965159529708617566513305767410411281312390712454933427103923155364510969621476018389741810262939741133340534653703395327282629417895706182454361725996471582545792614093160153904488325049687673053418888993964297510856687319573855686654677134409603366618418171, 7817831918146865794730809080381015534576184523606191689994617809921134511611842053899100199086993665124445014014312725824189063168251357803804249308757644094857555604663067302904380583248932622019808925596336474480462229522615361063690582269787948466689152030640270911053135661261341524231)
    Original Message: Hello, world!
    Encrypted Message: b'UqUVTGfnSISUXVRdTC7JyJYkoShhKnLRGv2f+pBv5yEbmhf1wCvXpWhLN/y/fV9Vdw3LQkbN3ChuH1Ya4HfSx9P7iLenzbJBgRkpXe5ZJQTgaIf7dTmcwf0cnqZbr4ffCgLDnPuw0thgaagy8gp+ER3Cic9Th13ui458dQeBjEn3Ub4ujomKIi2LTlcTEyXeRDZkdLu26wxDJRYxwwrn6licLSGgiL2mHIGhORp88N0F9omp+h/Y5XrhTTQx7kTQdJY1YmV5DfBLl1N0xSN3jN59SHqRZ48Nc+FTCDVAH7QxhTn/rrmxVhyxfYBkoJBg2MDME5+T8dW5b//jlONU/w=='
    Decrypted Message: Hello, world!
    Is message equal to decrypted message? True
    Signature: MrfXMOsz44QL4q6Nihvse0OnnfpmgAM6KW3OusAlfK5PIvi5Rvex9lecbnFq5p0II91zjJf5TArGbdE0OwtYfV/xa/LhvY5I9IPVn12iK8iRoWTq0s96Ovi7jxwExYlJQmrFWwtRNqivs5wnzz/4M7mRcEjBYEyJPR8MzLk3hw814lhz4A3wUDYkVXVMANT6fNewu9B8VVntuQzuIMBJxGcdFIJQGCai9+ba45/W/JCnxp/mn/Xzo+OlWw06rEa58qdAbBX23aOaUQpzLTLN8hNlaa1VJC5GwLoNPbevgtAvvokcx7DZwYSI/YVcBJ6uQi4wBhghOBVcEYdfsGW9pw==
    Is Valid Signature? True
"""