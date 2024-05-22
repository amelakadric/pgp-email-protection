import unittest
import PGPCore as pgpc
import base64

class PGPCoreTests(unittest.TestCase):

    def test_aes128_idemp(self):
        msgt = "This message is used to test functioning of aes128 implementation in PGPCore module"
        pgpt = pgpc.PGPCore(1, 2, msgt)
        pgpt.aes128()
        pgpt.encrypt()
        self.assertEqual(msgt, pgpt.decrypt().get_data())

    def test_3des_idemp(self):
        msgt = "This message is used to test functioning of tripple des (3des) implementation in PGPCore module"
        pgpt = pgpc.PGPCore(1, 2, msgt)
        pgpt.tripple_des()
        pgpt.encrypt()
        self.assertEqual(msgt, pgpt.decrypt().get_data())

if __name__ == '__main__':
    unittest.main()