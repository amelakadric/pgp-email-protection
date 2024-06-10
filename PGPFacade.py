from datetime import datetime
import PGPCore as pgpc
import mock_key_store as mks
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization

BYTE_SEPARATOR_SEQ = b"&???|||???&"
PART_BYTE_SEPARATOR_SEQ = b"{}{}***{}][{}***{}{}"

class PGPFacade():

    def __init__(self, sender_prk : RSAPrivateKey, sender_puk : RSAPublicKey, receiver_puk : RSAPublicKey):
        self.sender_prk = sender_prk
        self.sender_puk = sender_puk
        self.receiver_puk = receiver_puk
    
    # load serialized key -- serialization.load_der_public_key(key_id)
    def get_public_key_id(self, puk):
        return puk.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )[-64::]
    
    def save_to_file(self, data : bytes, filename : str):
        if not filename.endswith(".pgp"): filename += ".pgp"
        with open(filename, "wb") as f: f.write(data)

    def pgp_encrypt_message(self, data : bytes, filename : str, options : list):
        time_stamp1 = datetime.now()
        data += BYTE_SEPARATOR_SEQ + time_stamp1.__str__().encode() \
             + BYTE_SEPARATOR_SEQ + filename.encode() + PART_BYTE_SEPARATOR_SEQ
        # data.split(b"|") to split binary data on byte b"|"
        encr_engine = pgpc.PGPCore(self.sender_prk, self.sender_puk, data)
        msg_digest = encr_engine.data_signature()
        l2o_msg_digest = msg_digest[0:2]

        sender_puk_id = self.get_public_key_id(self.sender_puk)
        time_stamp2 = datetime.now()
        
        data += msg_digest + BYTE_SEPARATOR_SEQ + l2o_msg_digest \
            + BYTE_SEPARATOR_SEQ + sender_puk_id \
            + BYTE_SEPARATOR_SEQ + time_stamp2.__str__().encode()
            
        if "compression" in options:
            data = pgpc.PGPCore(self.sender_prk, self.sender_puk, data).zip().get_data()

        receiver_puk_id = self.get_public_key_id(self.receiver_puk)
        data += PART_BYTE_SEPARATOR_SEQ + receiver_puk_id

        self.save_to_file(data, filename)

if __name__ == "__main__":

    mprks = mks.MockPRKStore()
    mpuks = mks.MockPUKStore()
    sender_private_key = mprks.get_key_by_uid("prk1_2048", "password")
    sender_public_key = mpuks.get_key_by_uid("puk1_2048")
    receiver_public_key = mpuks.get_key_by_uid("puk1_2048")

    p1 = PGPFacade(sender_private_key, sender_public_key, receiver_public_key)
    p1.pgp_encrypt_message(b"abc"*1000000, "pgp_facade_test.pgp", ["compression"])

