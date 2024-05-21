import os
import hashlib as hl
import cryptography.hazmat.primitives.ciphers.algorithms as cphr_algo
import cryptography.hazmat.primitives.ciphers as cphr
from cryptography.hazmat.primitives.ciphers.modes import CFB

class PGPCore():

    """ This class contains all PGP's cryptographic operations """

    skey_size_in_bytes = 16 # 16B = 128b - size of session key
    tripple_des_block_size = 64
    aes128_block_size = 128

    def __init__(self, private_key : int, public_key : int, data):
        self.private_key = private_key
        self.public_key = public_key
        self.data = data

    def sha1(self):
        self.signature = hl.sha1(self.data)
        return self
    
    def generate_session_key(self):
        self.session_key = int.from_bytes(os.urandom(self.skey_size_in_bytes), byteorder="big")
    
    def tripple_des(self):
        self.iv = int.from_bytes(os.urandom(self.tripple_des_block_size), byteorder="big")
        cipher = cphr.Cipher(cphr_algo.TripleDES, mode=cphr.modes.CFB(self.iv))

    def aes128(self):
        self.iv = int.from_bytes(os.urandom(self.aes128_block_size), byteorder="big")
        cipher = cphr.Cipher(cphr_algo.AES128, mode=cphr.modes.CFB(self.iv))
    
