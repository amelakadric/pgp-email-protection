import os
import hashlib as hl
import cryptography.hazmat.primitives.ciphers.algorithms as cphr_algo
import cryptography.hazmat.primitives.ciphers as cphr
from cryptography.hazmat.primitives.ciphers.modes import CFB

class PGPCore():

    """ This class contains all PGP's cryptographic operations """

    skey_size_in_bytes = 16 # 16B = 128b - size of session key
    tripple_des_block_size = 8 # 8B = 64b
    aes128_block_size = 16 # 16B = 128b

    def __init__(self, private_key : int, public_key : int, data, session_key=None, iv=None):
        self.private_key = private_key
        self.public_key = public_key
        self.data = data
        # symmetric algorithm parameters
        self.session_key = session_key
        self.iv = iv
        self.signature = None

    def get_data(self):
        return self.data

    def get_signature(self):
        return self.signature
    
    def sha1(self):
        self.signature = hl.sha1(self.data)
        return self
    
    def generate_session_key(self):
        self.session_key = os.urandom(self.skey_size_in_bytes)
    
    def tripple_des(self):
        if self.session_key is None: self.generate_session_key()
        if self.iv is None: self.iv = os.urandom(self.tripple_des_block_size)
        cipher = cphr.Cipher(cphr_algo.TripleDES(self.session_key), mode=cphr.modes.CFB(self.iv))
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def aes128(self):
        if self.session_key is None: self.generate_session_key()
        if self.iv is None: self.iv = os.urandom(self.aes128_block_size)
        cipher = cphr.Cipher(cphr_algo.AES128(self.session_key), mode=cphr.modes.CFB(self.iv))
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def encrypt(self):
        self.data = self.encryptor.update(bytes(self.data, encoding="UTF-8")) + self.encryptor.finalize()
        return self
    
    def decrypt(self):
        self.data = self.decryptor.update(self.data) + self.decryptor.finalize()
        self.data = self.data.decode(encoding="UTF-8")
        return self
    
