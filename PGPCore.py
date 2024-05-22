import os
import hashlib as hl
import cryptography.hazmat.primitives.ciphers.algorithms as cphr_algo
import cryptography.hazmat.primitives.ciphers as cphr
from cryptography.hazmat.primitives.ciphers.modes import CFB
import zipfile as zf

class PGPCore():

    """ This class contains all PGP's cryptographic operations """

    skey_size_in_bytes = 16 # 16B = 128b - size of session key
    tripple_des_block_size = 8 # 8B = 64b
    aes128_block_size = 16 # 16B = 128b
    temp_data_file = "temp_data.txt"

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
        self.session_key = os.urandom(self.skey_size_in_bytes)
        return self
    
    def tripple_des(self):
        if self.session_key is None: self.generate_session_key()
        if self.iv is None: self.iv = os.urandom(self.tripple_des_block_size)
        cipher = cphr.Cipher(cphr_algo.TripleDES(self.session_key), mode=cphr.modes.CFB(self.iv))
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()
        return self

    def aes128(self):
        if self.session_key is None: self.generate_session_key()
        if self.iv is None: self.iv = os.urandom(self.aes128_block_size)
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
        os.remove(self.temp_data_file)
        return self

    def write_data_to_tmp(self):
        if type(self.data) == str:
            with open(self.temp_data_file, "w") as f: f.write(self.data)
        else:
            with open(self.temp_data_file, "wb") as f: f.write(self.data)
        return self
    
    def read_data_from_temp(self):
        try:
            with open(self.temp_data_file, "r") as f: self.data = f.read()
        except UnicodeDecodeError as e:
            with open(self.temp_data_file, "rb") as f: self.data = f.read()
        self.del_temp_data()
        return self
    
    def zip_to_file(self, filename: str):
        if not filename.endswith(".zip"): filename += ".zip"
        self.write_data_to_tmp()
        with zf.ZipFile(filename, "w") as zipf:
            zipf.write(self.temp_data_file)
        self.del_temp_data()
        return self
    
    def unzip_from_file(self, filename: str):
        if not filename.endswith(".zip"): filename += ".zip"
        with zf.ZipFile(filename, "r") as zipf:
            zipf.extract(member=self.temp_data_file, path="./arch_" + self.temp_data_file)
        os.replace("./arch_" + self.temp_data_file + "/" + self.temp_data_file, "./" + self.temp_data_file)
        os.rmdir("./arch_" + self.temp_data_file)
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

        
    
