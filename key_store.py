# import key_store_interface.PublicKeyStore as PublicKeyStoreInterface  # type: ignore
# import key_store_interface.PrivateKeyStore as PrivateKeyStoreInterface  # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime


class PublicKeyStore():
    
    def __init__(self):
        if hasattr(self, '_initialized'):  # Check if already initialized
            return
        self.keys_by_kid = {}  # Dictionary to store keys by key ID
        self.keys_by_uid = {}  # Dictionary to store lists of keys by user ID

    def add_key(self, public_key: rsa.RSAPublicKey, user_id: str):
        key_id = public_key.public_numbers().n % (2 ** 64)
        timestamp = datetime.now()
        self.keys_by_kid[key_id] = (public_key, timestamp)
        if user_id not in self.keys_by_uid:
            self.keys_by_uid[user_id] = []
        self.keys_by_uid[user_id].append((public_key, timestamp))

    def remove_key(self, key_id):
        if key_id in self.keys_by_kid:
            public_key, _ = self.keys_by_kid.pop(key_id)
            # Remove from user IDs as well
            for user_id, keys in self.keys_by_uid.items():
                for key in keys:
                    if key[0] == public_key:
                        keys.remove(key)
                        if not keys:
                            del self.keys_by_uid[user_id]
                        break

    def get_key_by_kid(self, keyId: int) -> rsa.RSAPublicKey:
        key_entry = self.keys_by_kid.get(keyId, None)
        return key_entry[0] if key_entry else None
    
    def get_key_by_uid(self, userId: str) -> list:
        return [key[0] for key in self.keys_by_uid.get(userId, [])]

    def export_key(self, key_id, filepath):
        key_entry = self.keys_by_kid.get(key_id, None)
        if key_entry:
            key = key_entry[0]
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(filepath, 'wb') as pem_out:
                pem_out.write(pem)
    
    def import_key(self, filepath, user_id):
        with open(filepath, 'rb') as pem_in:
            pem_data = pem_in.read()
            public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
            self.add_key(public_key, user_id)


class PrivateKeyStore():

    def __init__(self):
        if hasattr(self, '_initialized'):  # Check if already initialized
            return
        self.keys_by_kid = {}  # Dictionary to store keys by key ID
        self.keys_by_uid = {}  # Dictionary to store lists of keys by user ID
        self._initialized = True


    def add_key(self, public_key: rsa.RSAPublicKey, private_key: rsa.RSAPrivateKey, user_id: str, key_passwd: str):
        key_id = public_key.public_numbers().n % (2 ** 64)
        timestamp = datetime.now()

        # Encrypt the private key using BestAvailableEncryption
        encrypted_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key_passwd.encode())
        )
        
        self.keys_by_kid[key_id] = (encrypted_private_key, key_passwd, timestamp)
        if user_id not in self.keys_by_uid:
            self.keys_by_uid[user_id] = []
        self.keys_by_uid[user_id].append((encrypted_private_key, key_passwd, timestamp))

    def remove_key(self, key_id):
        if key_id in self.keys_by_kid:
            private_key_tuple = self.keys_by_kid.pop(key_id)
            # Remove from user IDs as well
            for user_id, keys in self.keys_by_uid.items():
                for key in keys:
                    if key[0] == private_key_tuple[0]:
                        keys.remove(key)
                        if not keys:
                            del self.keys_by_uid[user_id]
                        break

    def get_key_by_kid(self, keyId: int, key_passwd: str) -> rsa.RSAPrivateKey:
        key_entry = self.keys_by_kid.get(keyId, None)
        if key_entry and key_entry[1] == key_passwd:
            return serialization.load_pem_private_key(key_entry[0], password=key_passwd.encode(), backend=default_backend())
        return None
    
    def get_key_by_uid(self, userId: str, key_passwd: str) -> list:
        keys = self.keys_by_uid.get(userId, [])
        return [serialization.load_pem_private_key(key[0], password=key_passwd.encode(), backend=default_backend()) for key in keys if key[1] == key_passwd]

    def export_key(self, key_id, filepath, key_passwd):
        key_entry = self.keys_by_kid.get(key_id, None)
        if key_entry and key_entry[1] == key_passwd:
            with open(filepath, 'wb') as pem_out:
                pem_out.write(key_entry[0])

    def import_key(self, filepath, user_id, key_passwd):
        with open(filepath, 'rb') as pem_in:
            pem_data = pem_in.read()
            private_key = serialization.load_pem_private_key(pem_data, password=key_passwd.encode(), backend=default_backend())
            public_key = private_key.public_key()
            self.add_key(public_key, private_key, user_id, key_passwd)
