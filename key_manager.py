import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from key_store import PrivateKeyStore, PublicKeyStore

class KeyManager:
    def __init__(self):
        self.public_key_store = PublicKeyStore()
        self.private_key_store = PrivateKeyStore()
    
    def get_public_key_store(self):
        return self.public_key_store
    
    def get_private_key_store(self):
        return self.private_key_store

    def generate_key_pair(self, name, email, password, key_size):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        self.public_key_store.add_key(public_key, email, name)
        self.private_key_store.add_key(public_key, private_key, email, password, name)

        print(f"Generated {key_size}-bit key pair for {name} ({email}).")

    def list_private_key_ring(self):
        key_ring = []

        # Collect public and private keys
        for key_id, key_info in self.private_key_store.keys_by_kid.items():
            encrypted_private_key, key_passwd_hash, email, timestamp, name = key_info
            public_key = self.public_key_store.get_key_by_kid(key_id)

            if public_key:
                key_ring.append({
                    "timestamp": timestamp.isoformat(),
                    "name": name,
                    "key_id":   str( key_id),
                    "public_key": public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode(),
                    "private_key": encrypted_private_key.decode('utf-8'),
                    "user_id": email
                })

        return {"private_key_ring": key_ring}

    def list_public_key_ring(self):
        public_keys = []
        for key_id, key_data in self.public_key_store.public_key_ring.items():
            public_key, user_id, timestamp, name = key_data
            public_keys.append({
                "user_id": user_id,
                "public_key": public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                "timestamp": timestamp.isoformat(),
                "key_id": str(key_id),
                "name": name
            })
        return {"public_key_ring": public_keys}

        

    def remove_key(self, key_id):
        self.public_key_store.remove_key(key_id)
        self.private_key_store.remove_key(key_id)
        print(f"Removed key with ID: {key_id}")

    def access_private_key(self, key_id, password):
        private_key = self.private_key_store.get_key_by_kid(key_id, password)
        if private_key:
            print(f"Access granted to private key: {private_key}")
        else:
            print("Access denied. Incorrect password or key not found.")

    def get_public_key_by_id(self, key_id):
        public_key = self.public_key_store.get_key_by_kid(key_id)
        if public_key:
            return {
                "public_key": public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                "key_id": str(key_id)
            }
        else:
            return None

    def get_private_key_by_id(self, key_id, password):
        private_key = self.private_key_store.get_key_by_kid(key_id, password)
        if not private_key:
            return None  # Access denied
        if private_key:
            return {
                "private_key": private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode(),
                "key_id": key_id
            }
        else:
            return None

    def get_public_keys_by_user_id(self, user_id):
        public_keys = self.public_key_store.get_key_by_uid(user_id)
        return [
            {
                "public_key": public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                "user_id": user_id
            }
            for public_key in public_keys
        ]

    def get_private_keys_by_user_id(self, user_id, password):
        private_keys = self.private_key_store.get_key_by_uid(user_id, password)
        if not private_keys:
            return None  # Access denied
        return [
            {
                "private_key": private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode(),
                "user_id": user_id
            }
            for private_key in private_keys
        ]
    
    def get_public_key_by_name(self, name):
        public_key = self.public_key_store.get_key_by_name(name)
        if public_key:
            return {
                "public_key": public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                "name": name
            }
        else:
            return None

    def get_private_key_by_name(self, name, password):
        private_key = self.private_key_store.get_key_by_name(name, password)
        if private_key:
            return {
                "private_key": private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode(),
                "name": name
            }
        else:
            return None

    def import_key(self, file_content, user_id, key_passwd, name):
        return self.private_key_store.import_key(file_content, user_id, key_passwd, name, public_key_store=self.public_key_store)
    
    def export_public_key(self, key_id, filepath):
        return self.public_key_store.export_key(key_id, filepath)

    def export_private_key(self, key_id, filepath, key_passwd):
        return self.private_key_store.export_key(key_id, filepath, key_passwd)

    def import_public_key(self, file_content, user_id, name):
        return self.public_key_store.import_public_key(file_content, user_id, name)
    
