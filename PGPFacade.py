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

    def get_public_key_id(self, puk):
        return puk.public_numbers().n % (2 ** 64)
    
    def save_to_pgp_file(self, data : bytes, filename : str):
        if not filename.endswith(".pgp"): filename += ".pgp"
        with open(filename, "wb") as f: f.write(data)

    def load_pgp_file(self, filename : str) -> bytes:
        if not filename.endswith(".pgp"): filename += ".pgp"
        data = None
        with open(filename, "rb") as f: data = f.read()
        return data
    
    def encr_sign_message(self, data):
        encr_engine = pgpc.PGPCore(self.sender_prk, self.sender_puk, data)
        msg_digest = encr_engine.data_signature()
        l2o_msg_digest = msg_digest[0:2]
        sender_puk_id = self.get_public_key_id(self.sender_puk)
        data += msg_digest + BYTE_SEPARATOR_SEQ + \
            l2o_msg_digest + BYTE_SEPARATOR_SEQ + \
            str(sender_puk_id).encode() + BYTE_SEPARATOR_SEQ
        return data
    
    def encr_compression(self, data):
        data = pgpc.PGPCore(self.sender_prk, self.sender_puk, data).zip().get_data()
        return data
    
    def encr_aes(self, data):
        aes_pgp_encryptor = pgpc.PGPCore(self.sender_prk, self.sender_puk, data).aes128().encrypt()
        data = aes_pgp_encryptor.get_data()
        aes_sk = pgpc.PGPCore(None, self.receiver_puk, aes_pgp_encryptor.get_session_key()).rsa_publ_encry().get_data()
        aes_iv = pgpc.PGPCore(None, self.receiver_puk, aes_pgp_encryptor.get_iv()).rsa_publ_encry().get_data()
        return data, aes_sk, aes_iv
    
    def encr_3des(self, data):
        des3_pgp_encryptor = pgpc.PGPCore(self.sender_prk, self.sender_puk, data).tripple_des().encrypt()
        data = des3_pgp_encryptor.get_data()
        des3_sk = pgpc.PGPCore(None, self.receiver_puk, des3_pgp_encryptor.get_session_key()).rsa_publ_encry().get_data()
        des3_iv = pgpc.PGPCore(None, self.receiver_puk, des3_pgp_encryptor.get_iv()).rsa_publ_encry().get_data()
        return data, des3_sk, des3_iv
    
    def encr_radix64(self, data):
        data = pgpc.PGPCore(self.sender_prk, self.sender_puk, data).radix64_encode().get_data()
        return data

    def pgp_encrypt_message(self, data : bytes, filename : str, options : list):
        time_stamp1 = datetime.now()
        data += BYTE_SEPARATOR_SEQ + time_stamp1.__str__().encode() \
             + BYTE_SEPARATOR_SEQ + filename.encode() + PART_BYTE_SEPARATOR_SEQ
        if "sign_msg" in options: data = self.encr_sign_message(data)
        time_stamp2 = datetime.now(); data +=  time_stamp2.__str__().encode()
        if "compression" in options: data = self.encr_compression(data)
        aes_sk = None; aes_iv = None; des3_sk = None; des3_iv = None
        if "aes_encrypt" in options: data, aes_sk, aes_iv = self.encr_aes(data)
        if "3des_encrypt" in options: data, des3_sk, des3_iv = self.encr_3des(data)
        data += PART_BYTE_SEPARATOR_SEQ
        if "aes_encrypt" in options: data += aes_sk + BYTE_SEPARATOR_SEQ + aes_iv + BYTE_SEPARATOR_SEQ
        if "3des_encrypt" in options: data += des3_sk + BYTE_SEPARATOR_SEQ + des3_iv + BYTE_SEPARATOR_SEQ
        data +=  str(self.get_public_key_id(self.receiver_puk)).encode()
        if "radix64" in options: data = self.encr_radix64(data)
        self.save_to_pgp_file(data, filename)


    def decr_radix64(self, msg_data):
        msg_data = pgpc.PGPCore(None, None, msg_data).radix64_decode().get_data()
        return msg_data
    
    def decr_decrypt_session_key_component(self, session_key_component, passwd):
        receiver_kid = int(session_key_component[-1].decode())
        receiver_prk : RSAPrivateKey = self.private_ks.get_key_by_kid(receiver_kid, passwd)
        for i in range(len(session_key_component) - 1):
            session_key_component[i] = pgpc.PGPCore(
                receiver_prk, None, session_key_component[i]).rsa_priv_decry().get_data()
        return session_key_component
    
    def decr_3des(self, processed_data, session_key_component, options):
        des3_sk = session_key_component[0]
        des3_iv = session_key_component[1]
        if "aes_encrypt" in options:
            des3_sk = session_key_component[2]
            des3_iv = session_key_component[3]
        des3_decryptor = pgpc.PGPCore(None, None, processed_data, des3_sk, des3_iv)
        processed_data = des3_decryptor.tripple_des().decrypt().get_data()
        return processed_data
    
    def decr_aes(self, processed_data, session_key_component):
        aes_sk = session_key_component[0]
        aes_iv = session_key_component[1]
        aes_decryptor = pgpc.PGPCore(None, None, processed_data, aes_sk, aes_iv)
        processed_data = aes_decryptor.aes128().decrypt().get_data()
        return processed_data
    
    def decr_compression(self, processed_data):
        processed_data = pgpc.PGPCore(None, None, processed_data).unzip().get_data()
        return processed_data
    
    def decr_sign_message(self, signature_component, message_component):
        time_stamp2  = signature_component[3]
        sender_key_id = signature_component[2]
        l2o_msg_digest = signature_component[1]
        msg_digest = signature_component[0]
        if l2o_msg_digest != msg_digest[0:2]:
            raise Exception("signature not received correctly")
        sender_puk : RSAPublicKey = self.public_ks.get_key_by_kid(int(sender_key_id.decode()))
        pgpc.PGPCore(None, sender_puk, BYTE_SEPARATOR_SEQ.join(message_component) + PART_BYTE_SEPARATOR_SEQ) \
            .verify_data_signature(msg_digest)

    
    def pgp_decrypt_message(self, filename : str, passwd : str, options : list):
        msg_data = self.load_pgp_file(filename)
        if "radix64" in options: msg_data = self.decr_radix64(msg_data)
        msg_data_parts = msg_data.split(PART_BYTE_SEPARATOR_SEQ)

        processed_data, session_key_component, signature_component, message_component = None, None, None, None
        if "compression" in options or "aes_encrypt" in options or "3des_encrypt" in options:
            session_key_component = msg_data_parts[1].split(BYTE_SEPARATOR_SEQ)
            processed_data = msg_data_parts[0]
            session_key_component = self.decr_decrypt_session_key_component(session_key_component, passwd)

        if "3des_encrypt" in options:
            processed_data = self.decr_3des(processed_data, session_key_component, options)

        if "aes_encrypt" in options:
            processed_data = self.decr_aes(processed_data, session_key_component)

        if "compression" in options:
            processed_data = self.decr_compression(processed_data)

        if "compression" not in options and "aes_encrypt" not in options and "3des_encrypt" not in options:
            session_key_component = msg_data_parts[2].split(BYTE_SEPARATOR_SEQ)
            signature_component = msg_data_parts[1].split(BYTE_SEPARATOR_SEQ)
            message_component = msg_data_parts[0].split(BYTE_SEPARATOR_SEQ)
        else:
            split_processed_data = processed_data.split(PART_BYTE_SEPARATOR_SEQ)
            signature_component = split_processed_data[1].split(BYTE_SEPARATOR_SEQ)
            message_component = split_processed_data[0].split(BYTE_SEPARATOR_SEQ)

        if "sign_msg" in options:
            self.decr_sign_message(signature_component, message_component)
        else: time_stamp2  = signature_component[0]

        filename = message_component[2]
        time_stamp1 = message_component[1]
        data = message_component[0]
        return data.decode("utf-8")

# tests for this class
if __name__ == "__main__":

    # test all combinations of options
    p1 = PGPFacade(mks.MockPRKStore(), mks.MockPUKStore())
    p1.set_send_msg_params(
        sender_prk_id="prk1_2048", sender_prk_passwd="password",
        sender_puk_id="puk1_2048", receiver_puk_id="puk1_2048"
    )
    all_passed = True
    test_data = b"abcdefgh" * 111
    options = ["compression", "radix64", "sign_msg", "aes_encrypt", "3des_encrypt"]
    sub_options = None
    for i in range(1 << len(options)):
        sub_options = [options[j] for j in range(len(options)) if (i & (1 << j))]
        p1.pgp_encrypt_message(test_data, "pgp_facade_test.pgp", sub_options)
        rez = p1.pgp_decrypt_message("pgp_facade_test.pgp", "password", sub_options)
        if rez != test_data.decode("utf-8"):
            all_passed = False; break
    if all_passed: print(" [*]\tAll tests passed")
    else: print(" [X]\tTest failed -- fail options: " + str(sub_options))

