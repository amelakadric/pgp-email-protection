import os
import hashlib as hl
import cryptography.hazmat.primitives.ciphers.algorithms as cphr_algo
import cryptography.hazmat.primitives.ciphers as cphr
from cryptography.hazmat.primitives.ciphers.modes import CFB
import zipfile as zf

class PGPCore():

    """ This class contains all PGP's cryptographic operations """

    SKEY_SIZE_IN_BYTES = 16 # 16B = 128b - size of session key
    TRIPPLE_DES_BLOCK_SIZE = 8 # 8B = 64b
    AES128_BLOCK_SIZE = 16 # 16B = 128b
    TEMP_DATA_FILE = "temp_data.txt"

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
        self.signature = hl.sha1(self.data).digest()
        return self
    
    def generate_session_key(self):
        self.session_key = os.urandom(self.SKEY_SIZE_IN_BYTES)
        return self
    
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
        self.data = self.encryptor.update(bytes(self.data, encoding="UTF-8")) + self.encryptor.finalize()
        return self
    
    def decrypt(self):
        self.data = self.decryptor.update(self.data) + self.decryptor.finalize()
        self.data = self.data.decode(encoding="UTF-8")
        return self
    
    def del_temp_data(self):
        os.remove(self.TEMP_DATA_FILE)
        return self

    def write_data_to_tmp(self):
        if type(self.data) == str:
            with open(self.TEMP_DATA_FILE, "w") as f: f.write(self.data)
        else:
            with open(self.TEMP_DATA_FILE, "wb") as f: f.write(self.data)
        return self
    
    def read_data_from_temp(self):
        try:
            with open(self.TEMP_DATA_FILE, "r") as f: self.data = f.read()
        except UnicodeDecodeError as e:
            with open(self.TEMP_DATA_FILE, "rb") as f: self.data = f.read()
        self.del_temp_data()
        return self
    
    def zip_to_file(self, filename: str):
        if not filename.endswith(".zip"): filename += ".zip"
        self.write_data_to_tmp()
        with zf.ZipFile(filename, "w") as zipf:
            zipf.write(self.TEMP_DATA_FILE)
        self.del_temp_data()
        return self
    
    def unzip_from_file(self, filename: str):
        if not filename.endswith(".zip"): filename += ".zip"
        with zf.ZipFile(filename, "r") as zipf:
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
