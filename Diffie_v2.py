from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from secrets import token_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import hmac
import os


##  -> alice tem random private = 15
##  -> alice calcula 3^15 mod 17 == 6
##  -> envia o 6 publico para bob 
##  -> bob tem random private 13
##  -> bob calcula 3^13 mod 17 == 12
##  -> envia o 6 publico para alice
##  
##  -> alice pega no publico de bob
##  -> alice pegae e calcula 12^15 mod 17 == 10    (10 é a shared secret)
##  -> bob pega no publico de alice   
##  -> bob pega e calcula 6^13 mod 17 == 10       (10 é a shared secret)

## basicamente alice faz    (3^13)^15 mod 17
## basicamente alice faz    (3^15)^13 mod 17


##  primeiro geramos a sharedKey

## a sharekey hey vai passar para a key derivation

class DiffieHellman:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend()) # aqui vai ser a nossa chave privada
        self.publicKey = self.private_key.public_key()                                   # aqui vai ser a partir da nossa  chave privada
        

    def getIV(self):
        return self.IV

    # key derivation
    def getKdfKey(self):
        kdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=None, backend=default_backend())
        return kdf

    def shared_key(self, publicKey):
        return self.private_key.exchange(ec.ECDH(), publicKey)  ## shared key, tem de ser igual

    def hmac_sha512(self, msg, publicKey):
        return hmac.new(msg, self.shared_key(publicKey), hashlib.sha512)

    def encrypt(self, publicKey, secret):
        self.IV = token_bytes(16)
        shared_key = self.shared_key( publicKey )
        
        key = self.getKdfKey()
        kdf = key.derive(shared_key)

        cypher = Cipher(algorithms.AES(kdf), modes.CBC(self.IV), default_backend())

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        return (cypher.encryptor()).update(padder.update(secret.encode()) + padder.finalize()) + (cypher.encryptor()).finalize()

    def decrypt(self, publicKey, secret, iv):
        shared_key = self.shared_key( publicKey )
        key = self.getKdfKey()
        kdf = key.derive(shared_key)

        cypher = Cipher(algorithms.AES(kdf), modes.CBC(iv), default_backend())

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update((cypher.decryptor()).update(secret) + (cypher.decryptor()).finalize()) + unpadder.finalize()