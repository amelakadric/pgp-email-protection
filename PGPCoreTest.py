import key_store_interface as ksi
import unittest
import mock_key_store as mks
import PGPCore as pgpc
import os
from cryptography.exceptions import InvalidSignature

class PGPCoreTests(unittest.TestCase):

    def test_aes128_idemp(self):
        msgt = b"This message is used to test functioning of aes128 implementation in PGPCore module"
        pgpt = pgpc.PGPCore(1, 2, msgt)
        pgpt.aes128()
        pgpt.encrypt()
        self.assertEqual(msgt, pgpt.decrypt().get_data())

    def test_3des_idemp(self):
        msgt = b"This message is used to test functioning of tripple des (3des) implementation in PGPCore module"
        pgpt = pgpc.PGPCore(1, 2, msgt)
        pgpt.tripple_des()
        pgpt.encrypt()
        self.assertEqual(msgt, pgpt.decrypt().get_data())
    
    def test_sha1_signature(self):
        result = b'\xfd\xfe6\xe5\xb7\xa1\xc2O\xbc\x87\xe6\xf2u\xb6\xee~\xd7:\xfc\x94'
        pgpt = pgpc.PGPCore(5, 6, b"message for testing sha1 message digest")
        self.assertEqual(pgpt.sha1(), result)
    
    def test_zip_file_idemp(self):
        tdata = b"Data to test zip\\unzip from\\to file. " * 15
        pgpt = pgpc.PGPCore(7, 8, tdata)
        pgpt.zip_to_file("file1")
        pgpt.zip_to_file("file2.zip")
        pgpt.unzip_from_file("file1.zip")
        self.assertEqual(pgpt.get_data(), tdata)
        pgpt.unzip_from_file("file2")
        self.assertEqual(pgpt.get_data(), tdata)
        os.remove("file1.zip")
        os.remove("file2.zip")
    
    def test_zip_idemp(self):
        tdata = b"Data to test zip\\unzip \"in memory\" idempotence" * 200
        pgpt = pgpc.PGPCore(9, 10, tdata)
        pgpt.zip().unzip()
        self.assertEqual(pgpt.get_data(), tdata)
    
    def test_rsa_puk_encr_prk_decr_idemp(self):
        tdata = b"Data to test RSA public\\private key encr\\decr idempotence"
        mprks = mks.MockPRKStore()
        mpuks = mks.MockPUKStore()
        pgpt = pgpc.PGPCore(
            mprks.get_key_by_uid("prk1_2048", "password"),
            mpuks.get_key_by_uid("puk1_2048"),
            tdata
        )
        pgpt.rsa_publ_encry().rsa_priv_decry()
        self.assertEqual(pgpt.get_data(), tdata)

    def test_rsa_prk_sign_puk_verify(self):
        tdata = b"Data to test RSA public\\private key encr\\decr idempotence"
        mprks = mks.MockPRKStore()
        mpuks = mks.MockPUKStore()
        pgpt = pgpc.PGPCore(
            mprks.get_key_by_uid("prk1_2048", "password"),
            mpuks.get_key_by_uid("puk1_2048"),
            tdata
        )
        signature = pgpt.data_signature()
        try:
            self.assertIsNone(pgpt.verify_data_signature(signature))
        except InvalidSignature:
            self.assertFalse()
    
    def test_radix64_idemp(self):
        tdata = b"Hello there, this is test string"
        pgpt = pgpc.PGPCore(7, 7, tdata)
        self.assertEqual(pgpt.radix64_encode().radix64_decode().get_data(), tdata)

if __name__ == '__main__':
    unittest.main()