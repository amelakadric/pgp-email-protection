import os
import hashlib as hl
import cryptography.hazmat.primitives.ciphers.algorithms as cphr_algo
import cryptography.hazmat.primitives.ciphers as cphr
from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import zipfile as zf
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
import codecs

class PGPCore():

    """ This class contains all PGP's cryptographic operations """

    SKEY_SIZE_IN_BYTES = 16 # 16B = 128b - size of session key
    TRIPPLE_DES_BLOCK_SIZE = 8 # 8B = 64b
    AES128_BLOCK_SIZE = 16 # 16B = 128b
    TEMP_DATA_FILE = "temp_data.tmp"

    def __init__(self, private_key, public_key, data, session_key=None, iv=None):
        self.private_key : RSAPrivateKey = private_key
        self.public_key : RSAPublicKey = public_key
        self.data = data
        # symmetric algorithm parameters
        self.session_key = session_key
        self.iv = iv

    def get_data(self):
        return self.data

    # this function is probably not going to get used
    def sha1(self):
        signature = hl.sha1(self.data).digest()
        return signature

    def data_signature(self):
        return self.private_key.sign(
            self.data, padding.PSS(
                mgf=padding.MGF1(hashes.SHA1()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA1()
        )

    def verify_data_signature(self, signature):
        return self.public_key.verify(
            signature, self.data, padding.PSS(
                mgf=padding.MGF1(hashes.SHA1()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA1()
        )
    
    def generate_session_key(self):
        self.session_key = os.urandom(self.SKEY_SIZE_IN_BYTES)
        return self
    
    def get_session_key(self):
        return self.session_key
    
    def tripple_des(self):
        if self.session_key is None: self.generate_session_key()
        if self.iv is None: self.iv = os.urandom(self.TRIPPLE_DES_BLOCK_SIZE)
        cipher = cphr.Cipher(cphr_algo.TripleDES(self.session_key), mode=cphr.modes.CFB(self.iv))
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()
        return self

    def aes128(self):
        if self.session_key is None: self.generate_session_key()
        if self.iv is None: self.iv = os.urandom(self.AES128_BLOCK_SIZE)
        cipher = cphr.Cipher(cphr_algo.AES128(self.session_key), mode=cphr.modes.CFB(self.iv))
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()
        return self

    def encrypt(self):
        self.data = self.encryptor.update(self.data) + self.encryptor.finalize()
        return self
    
    def decrypt(self):
        self.data = self.decryptor.update(self.data) + self.decryptor.finalize()
        #self.data = self.data.decode(encoding="UTF-8")
        return self
    
    def del_temp_data(self):
        os.remove(self.TEMP_DATA_FILE)
        return self

    def write_data_to_tmp(self):
        with open(self.TEMP_DATA_FILE, "wb") as f: f.write(self.data)
        return self
    
    def read_data_from_temp(self):
        with open(self.TEMP_DATA_FILE, "rb") as f: self.data = f.read()
        self.del_temp_data()
        return self
    
    def zip_to_file(self, filename: str):
        if not filename.endswith(".zip"): filename += ".zip"
        self.write_data_to_tmp()
        with zf.ZipFile(filename, "w", zf.ZIP_DEFLATED) as zipf:
            zipf.write(self.TEMP_DATA_FILE)
        self.del_temp_data()
        return self
    
    def unzip_from_file(self, filename: str):
        if not filename.endswith(".zip"): filename += ".zip"
        with zf.ZipFile(filename, "r", zf.ZIP_DEFLATED) as zipf:
            zipf.extract(member=self.TEMP_DATA_FILE, path="./arch_" + self.TEMP_DATA_FILE)
        os.replace("./arch_" + self.TEMP_DATA_FILE + "/" + self.TEMP_DATA_FILE, "./" + self.TEMP_DATA_FILE)
        os.rmdir("./arch_" + self.TEMP_DATA_FILE)
        self.read_data_from_temp()
        return self
    
    def zip(self):
        self.zip_to_file("tmp_data.zip")
        with open("tmp_data.zip", "rb") as f: self.data = f.read()
        os.remove("tmp_data.zip")
        return self
    
    def unzip(self):
        with open("tmp_data.zip", "wb") as f: f.write(self.data)
        self.unzip_from_file("tmp_data.zip")
        os.remove("tmp_data.zip")
        return self

    def rsa_publ_encry(self):
        self.data = self.public_key.encrypt(
            self.data, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None
            )
        )
        return self
    
    def rsa_priv_decry(self):
        self.data = self.private_key.decrypt(
            self.data, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None
            )
        )
        return self
    
    def radix64_encode(self):
        self.data = codecs.encode(self.data, "base64")
        return self

    def radix64_decode(self):
        self.data = codecs.decode(self.data, "base64")
        return self


