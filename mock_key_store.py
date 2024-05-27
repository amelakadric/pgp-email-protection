import key_store_interface as ksi
from cryptography.hazmat.primitives.asymmetric import rsa

# data for testing, shared between PUK and PRK key stores
key_data = dict()

private_kids = ["prk1_2048", "prk2_2048", "prk1_1024", "prk2_1024"]
public_kids = ["puk1_2048", "puk2_2048", "puk1_1024", "puk2_1024"]


# generate private keys
for pr_kid in private_kids:
    key_data[pr_kid] = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(pr_kid[-4::]),
    )

# generate public keys
for pu_kid in public_kids:
    key_data[pu_kid] = key_data[pu_kid.replace("u", "r")].public_key()

print(key_data)

class MockPUKStore(ksi.PublicKeyStore):

    def __init__(self):
        super.__init__()
        self.my_key_store = key_data
        self.my_kids = public_kids

    def get_key_by_kid(self, keyId : int) -> int:
        if not isinstance(keyId, int): raise Exception("keyId not of type int")
        if keyId in range(0, len(self.my_kids)):
            return self.my_key_store[self.my_kids[keyId]]
        return None

    def get_key_by_uid(self, userId : str) -> int:
        if not isinstance(userId, str): raise Exception("userId not of type string")
        if userId in self.my_kids:
            return self.my_key_store[userId]
        return None
    

class MockPRKStore(ksi.PrivateKeyStore):

    def __init__(self):
        super.__init__()
        self.my_key_store = key_data
        self.my_kids = private_kids

    def get_key_by_kid(self, keyId : int, key_passwd : str = None) -> int:
        if not isinstance(keyId, int): raise Exception("keyId not of type int")
        if key_passwd is None: raise Exception("Password not set for MockPKRStore")
        if not isinstance(key_passwd, str): raise Exception("Password not of type string")
        if keyId in range(0, len(self.my_kids)):
            return self.my_key_store[self.my_kids[keyId]]
        return None

    def get_key_by_uid(self, userId : str, key_passwd : str = None) -> int:
        if not isinstance(userId, str): raise Exception("userId not of type string")
        if key_passwd is None: raise Exception("Password not set for MockPKRStore")
        if not isinstance(key_passwd, str): raise Exception("Password not of type string")
        if userId in self.my_kids:
            return self.my_key_store[userId]
        return None