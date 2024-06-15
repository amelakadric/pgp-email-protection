import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import hashlib
from key_store_interface import PublicKeyStore as BasePublicKeyStore
from key_store_interface import PrivateKeyStore as BasePrivateKeyStore

class PublicKeyStore(BasePublicKeyStore):
    def __init__(self, filename='private_key_ring.json', public_ring_filename='public_key_ring.json'):
        self.filename = filename
        self.public_ring_filename = public_ring_filename
        self.load_keys()
        self.load_public_key_ring()

    def load_keys(self):
        try:
            with open(self.filename, 'r') as file:
                data = json.load(file)
                public_keys_data = data.get('public_key_store', {})
                self.keys_by_kid = {int(k): (self.deserialize_public_key(v[0]), v[1], datetime.fromisoformat(v[2]), v[3]) for k, v in public_keys_data.items()}
                self.keys_by_uid = {}
                for k, (public_key, user_id, timestamp, name) in self.keys_by_kid.items():
                    if user_id not in self.keys_by_uid:
                        self.keys_by_uid[user_id] = []
                    self.keys_by_uid[user_id].append((public_key, timestamp, name))
        except FileNotFoundError:
            self.keys_by_kid = {}
            self.keys_by_uid = {}

    def load_public_key_ring(self):
        try:
            with open(self.public_ring_filename, 'r') as file:
                data = json.load(file)
                public_keys_data = data.get('public_key_store', {})
                self.public_key_ring = {int(k): (self.deserialize_public_key(v[0]), v[1], datetime.fromisoformat(v[2]), v[3]) for k, v in public_keys_data.items()}
        except FileNotFoundError:
            self.public_key_ring = {}

    def save_keys(self):
        try:
            with open(self.filename, 'r') as file:
                data = json.load(file)
        except FileNotFoundError:
            data = {}

        public_keys_data = {str(k): [self.serialize_public_key(v[0]), v[1], v[2].isoformat(), v[3]] for k, v in self.keys_by_kid.items()}
        data['public_key_store'] = public_keys_data

        with open(self.filename, 'w') as file:
            json.dump(data, file, indent=4)

    def save_public_key_ring(self):
        public_keys_data = {str(k): [self.serialize_public_key(v[0]), v[1], v[2].isoformat(), v[3]] for k, v in self.public_key_ring.items()}
        data = {'public_key_store': public_keys_data}

        with open(self.public_ring_filename, 'w') as file:
            json.dump(data, file, indent=4)

    def add_key(self, public_key: rsa.RSAPublicKey, user_id: str, name: str):
        key_id = public_key.public_numbers().n % (2 ** 64)
        timestamp = datetime.now()
        self.keys_by_kid[key_id] = (public_key, user_id, timestamp, name)
        if user_id not in self.keys_by_uid:
            self.keys_by_uid[user_id] = []
        self.keys_by_uid[user_id].append((public_key, timestamp, name))
        self.save_keys()

    def add_public_key(self, public_key: rsa.RSAPublicKey, user_id: str, name: str):
        key_id = public_key.public_numbers().n % (2 ** 64)
        timestamp = datetime.now()
        self.public_key_ring[key_id] = (public_key, user_id, timestamp, name)
        self.save_public_key_ring()

    def remove_key(self, key_id):
        if key_id in self.keys_by_kid:
            public_key, user_id, _, name = self.keys_by_kid.pop(key_id)
            to_remove = []
            for uid, keys in self.keys_by_uid.items():
                for key in keys:
                    if key[0] == public_key:
                        to_remove.append((uid, key))
                        break
            for uid, key in to_remove:
                self.keys_by_uid[uid].remove(key)
                if not self.keys_by_uid[uid]:
                    del self.keys_by_uid[uid]
            self.save_keys()

    def get_key_by_kid(self, keyId: int) -> rsa.RSAPublicKey:
        key_entry = self.keys_by_kid.get(keyId, None)
        return key_entry[0] if key_entry else None

    def get_key_by_uid(self, userId: str) -> list:
        return [key[0] for key in self.keys_by_uid.get(userId, [])]

    def get_key_by_name(self, name: str) -> int:
        key = self.keys_by_name.get(name, None)
        return key.public_numbers().n if key else None

    def export_key(self, key_id, filepath):
        print(key_id)
        key_entry = self.keys_by_kid.get(key_id, None)
        if key_entry:
            key = key_entry[0]
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print(filepath)
            with open(filepath, 'wb+') as pem_out:
                pem_out.write(pem)
            return True
        else:
            return False

    def import_key(self, filepath, user_id, name):
        with open(filepath, 'rb') as pem_in:
            pem_data = pem_in.read()
            public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
            self.add_key(public_key, user_id, name)

    def import_public_key(self, file_content, user_id, name):
        try:
            public_key = serialization.load_pem_public_key(file_content.encode('utf-8'), backend=default_backend())
            self.add_public_key(public_key, user_id, name)
            return {"message": "Key imported successfully."}
        except Exception as e:
            return {"message": "Failed to import key.", "error": str(e)}
        
    @staticmethod
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    @staticmethod
    def deserialize_public_key(pem_data):
        return serialization.load_pem_public_key(
            pem_data.encode('utf-8'),
            backend=default_backend()
        )


class PrivateKeyStore(BasePrivateKeyStore):
    def __init__(self, filename='private_key_ring.json'):
        self.filename = filename
        self.load_keys()

    def load_keys(self):
        try:
            with open(self.filename, 'r') as file:
                data = json.load(file)
                private_keys_data = data.get('private_key_store', {})
                self.keys_by_kid = {int(k): (v[0].encode('utf-8'), v[1], v[2], datetime.fromisoformat(v[3]), v[4]) for k, v in private_keys_data.items()}
                self.keys_by_uid = {}
                for k, (encrypted_private_key, key_passwd_hash, user_id, timestamp, name) in self.keys_by_kid.items():
                    if user_id not in self.keys_by_uid:
                        self.keys_by_uid[user_id] = []
                    self.keys_by_uid[user_id].append((encrypted_private_key, key_passwd_hash, timestamp, name))
        except FileNotFoundError:
            self.keys_by_kid = {}
            self.keys_by_uid = {}

    def save_keys(self):
        try:
            with open(self.filename, 'r') as file:
                data = json.load(file)
        except FileNotFoundError:
            data = {}

        private_keys_data = {str(k): [v[0].decode('utf-8'), v[1], v[2], v[3].isoformat(), v[4]] for k, v in self.keys_by_kid.items()}
        data['private_key_store'] = private_keys_data

        with open(self.filename, 'w') as file:
            json.dump(data, file, indent=4)

    def add_key(self, public_key: rsa.RSAPublicKey, private_key: rsa.RSAPrivateKey, user_id: str, key_passwd: str, name: str):
        key_id = public_key.public_numbers().n % (2 ** 64)
        timestamp = datetime.now()

        # Hash the password using SHA-1
        key_passwd_hash = hashlib.sha1(key_passwd.encode()).hexdigest()

        encrypted_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key_passwd.encode())
        )

        self.keys_by_kid[key_id] = (encrypted_private_key, key_passwd_hash, user_id, timestamp, name)
        if user_id not in self.keys_by_uid:
            self.keys_by_uid[user_id] = []
        self.keys_by_uid[user_id].append((encrypted_private_key, key_passwd_hash, timestamp, name))
        self.save_keys()

    def remove_key(self, key_id):
        if key_id in self.keys_by_kid:
            private_key_tuple = self.keys_by_kid.pop(key_id)
            to_remove = []
            for user_id, keys in self.keys_by_uid.items():
                for key in keys:
                    if key[0] == private_key_tuple[0]:
                        to_remove.append((user_id, key))
                        break
            for user_id, key in to_remove:
                self.keys_by_uid[user_id].remove(key)
                if not self.keys_by_uid[user_id]:
                    del self.keys_by_uid[user_id]
            self.save_keys()


    def get_key_by_kid(self, keyId: int, key_passwd: str) -> rsa.RSAPrivateKey:
        key_entry = self.keys_by_kid.get(keyId, None)
        # Verify password using hashed password
        if key_entry and key_entry[1] == hashlib.sha1(key_passwd.encode()).hexdigest():
            return serialization.load_pem_private_key(key_entry[0], password=key_passwd.encode(), backend=default_backend())
        return None
    
    def get_key_by_uid(self, userId: str, key_passwd: str) -> list:
        keys = self.keys_by_uid.get(userId, [])
        # Verify password using hashed password
        return [serialization.load_pem_private_key(key[0], password=key_passwd.encode(), backend=default_backend()) for key in keys if key[1] == hashlib.sha1(key_passwd.encode()).hexdigest()]

    def get_key_by_name(self, name: str, key_passwd: str) -> rsa.RSAPrivateKey:
        key = self.keys_by_name.get(name, None)
        if key:
            return serialization.load_pem_private_key(key, password=key_passwd.encode(), backend=default_backend())
        return None

    def export_key(self, key_id, filepath, key_passwd):
        key_entry = self.keys_by_kid.get(key_id, None)
        # Verify password using hashed password
        if key_entry and key_entry[1] == hashlib.sha1(key_passwd.encode()).hexdigest():
            with open(filepath, 'wb') as pem_out:
                pem_out.write(key_entry[0])
                return True
        else:
            return False

    def import_key(self, filepath, user_id, key_passwd, name):
        try:
            with open(filepath, 'rb') as pem_in:
                pem_data = pem_in.read()
                private_key = serialization.load_pem_private_key(pem_data, password=key_passwd.encode(), backend=default_backend())
                public_key = private_key.public_key()
                self.add_key(public_key, private_key, user_id, key_passwd, name)
                return {"message": "Key imported successfully."}
        except Exception as e:
            return {"message": "Failed to import key.", "error": str(e)}

