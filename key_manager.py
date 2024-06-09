from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import getpass

from key_store import PrivateKeyStore, PublicKeyStore

class KeyManager:
    def __init__(self):
        self.public_key_store = PublicKeyStore()
        self.private_key_store = PrivateKeyStore()

    def generate_key_pair(self, name, email, password, key_size):
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        self.public_key_store.add_key(public_key, email)
        self.private_key_store.add_key(public_key, private_key, email, password)

        print(f"Generated {key_size}-bit key pair for {name} ({email}).")


    def list_keys(self):
        # Collect public keys
        public_keys = []
        for user_id, keys in self.public_key_store.keys_by_uid.items():
            for public_key, timestamp in keys:
                key_id = public_key.public_numbers().n % (2 ** 64)
                public_keys.append({
                    "user_id": user_id,
                    "public_key": public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode(),
                    "timestamp": timestamp,
                    "key_id": key_id
                })

        # Collect private keys
        private_keys = []
        for user_id, keys in self.private_key_store.keys_by_uid.items():
            for encrypted_private_key, key_passwd, timestamp in keys:
                # Decrypt the private key
                private_key = serialization.load_pem_private_key(
                    encrypted_private_key,
                    password=key_passwd.encode(),
                    backend=default_backend()
                )
                key_id = private_key.public_key().public_numbers().n % (2 ** 64)
                private_keys.append({
                    "user_id": user_id,
                    "encrypted_private_key": encrypted_private_key.decode(),
                    "timestamp": timestamp,
                    "key_id": key_id
                })


        return {"public_keys": public_keys, "private_keys": private_keys}
    

    def remove_key(self, key_id):
        self.public_key_store.remove_key(key_id)
        self.private_key_store.remove_key(key_id)
        print(f"Removed key with ID: {key_id}")

    
    def access_private_key(self, key_id):
        password = getpass.getpass("Enter the password for the private key: ")
        private_key = self.private_key_store.get_key_by_kid(key_id, password)
        if private_key:
            print(f"Access granted to private key: {private_key}")
        else:
            print("Access denied. Incorrect password or key not found.")
