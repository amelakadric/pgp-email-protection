from datetime import datetime
import PGPCore as pgpc
import mock_key_store as mks
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization
import key_store_interface as ksi

BYTE_SEPARATOR_SEQ = b"&???|||???&"
PART_BYTE_SEPARATOR_SEQ = b"{}{}***{}][{}***{}{}"

class PGPFacade():

    def __init__(self, private_ks: ksi.PrivateKeyStore, public_ks: ksi.PublicKeyStore):
        self.private_ks = private_ks
        self.public_ks = public_ks

    def set_send_msg_params(self, sender_prk_id, sender_prk_passwd : str, sender_puk_id, receiver_puk_id):
        self.sender_prk = None
        self.sender_puk = None
        self.receiver_puk = None

        if sender_prk_id is not None:
            if isinstance(sender_prk_id, int):
                self.sender_prk = self.private_ks.get_key_by_kid(sender_prk_id, sender_prk_passwd)
            elif isinstance(sender_prk_id, str):
                self.sender_prk = self.private_ks.get_key_by_uid(sender_prk_id, sender_prk_passwd)

        if sender_puk_id is not None:
            if isinstance(sender_puk_id, int):
                self.sender_puk = self.public_ks.get_key_by_kid(sender_puk_id)
            elif isinstance(sender_puk_id, str):
                self.sender_puk = self.public_ks.get_key_by_uid(sender_puk_id)

        if receiver_puk_id is not None:
            if isinstance(receiver_puk_id, int):
                self.receiver_puk = self.public_ks.get_key_by_kid(receiver_puk_id)
            elif isinstance(receiver_puk_id, str):
                self.receiver_puk = self.public_ks.get_key_by_uid(receiver_puk_id)

    def set_receiver_msg_params(self, sender_puk_id, receiver_puk_id, receiver_prk_id):
        self.sender_puk = None
        self.receiver_puk = None
        self.receiver_prk = None

        if sender_puk_id is not None:
            if isinstance(sender_puk_id, int):
                self.sender_puk = self.public_ks.get_key_by_kid(sender_puk_id)
            elif isinstance(sender_puk_id, str):
                self.sender_puk = self.public_ks.get_key_by_uid(sender_puk_id)

        if receiver_puk_id is not None:
            if isinstance(receiver_puk_id, int):
                self.receiver_puk = self.public_ks.get_key_by_kid(receiver_puk_id)
            elif isinstance(receiver_puk_id, str):
                self.receiver_puk = self.public_ks.get_key_by_uid(receiver_puk_id)

        if receiver_prk_id is not None:
            if isinstance(receiver_prk_id, int):
                self.receiver_prk = self.public_ks.get_key_by_kid(receiver_prk_id)
            elif isinstance(receiver_prk_id, str):
                self.receiver_prk = self.public_ks.get_key_by_uid(receiver_prk_id)
    
    # load serialized key -- serialization.load_der_public_key(key_id)
    def get_public_key_id(self, puk):
        return puk.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )[-64::]
    
    def save_to_pgp_file(self, data : bytes, filename : str):
        if not filename.endswith(".pgp"): filename += ".pgp"
        with open(filename, "wb") as f: f.write(data)

    def load_pgp_file(self, filename : str) -> bytes:
        if not filename.endswith(".pgp"): filename += ".pgp"
        data = None
        with open(filename, "rb") as f: data = f.read()
        return data

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
        if "radix64" in options:
            data = pgpc.PGPCore(self.sender_prk, self.sender_puk, data).radix64_encode().get_data()
        self.save_to_pgp_file(data, filename)
    
    def pgp_decrypt_message(self, filename : str, options : list):
        msg_data = self.load_pgp_file(filename)
        if "radix64" in options:
            msg_data = pgpc.PGPCore(self.receiver_prk, self.receiver_puk, msg_data).radix64_decode().get_data()
        msg_data_parts = msg_data.split(PART_BYTE_SEPARATOR_SEQ)
        session_key_component = None; signature_component = None; message_component = None
        if "compression" in options:
            session_key_component = msg_data_parts[1].split(BYTE_SEPARATOR_SEQ)
            uncompressed_split_data = pgpc.PGPCore(1, 1, msg_data_parts[0]) \
                .unzip().get_data().split(PART_BYTE_SEPARATOR_SEQ)
            signature_component = uncompressed_split_data[1].split(BYTE_SEPARATOR_SEQ)
            message_component = uncompressed_split_data[0].split(BYTE_SEPARATOR_SEQ)
        else:
            session_key_component = msg_data_parts[2].split(BYTE_SEPARATOR_SEQ)
            signature_component = msg_data_parts[1].split(BYTE_SEPARATOR_SEQ)
            message_component = msg_data_parts[0].split(BYTE_SEPARATOR_SEQ)

        recipient_key_id = session_key_component[0]

        time_stamp2  = signature_component[3]
        sender_key_id = signature_component[2]
        l2o_msg_digest = signature_component[1]
        msg_digest = signature_component[0]

        filename = message_component[2]
        time_stamp1 = message_component[1]
        data = message_component[0]
        print(data.decode("utf-8"))





if __name__ == "__main__":

    p1 = PGPFacade(mks.MockPRKStore(), mks.MockPUKStore())
    p1.set_send_msg_params(
        sender_prk_id="prk1_2048", sender_prk_passwd="password",
        sender_puk_id="puk1_2048", receiver_puk_id="puk1_2048"
    )
    p1.pgp_encrypt_message(b"abc"*10, "pgp_facade_test.pgp", ["compression", "radix64"])
    p1.set_receiver_msg_params(sender_puk_id="puk1_2048", receiver_puk_id="puk1_2048", receiver_prk_id="prk1_2048")
    p1.pgp_decrypt_message("pgp_facade_test.pgp", ["compression", "radix64"])

