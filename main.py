print("Hello world")

import key_store_interface as ksi

puks = ksi.PublicKeyStore()
prks = ksi.PrivateKeyStore()

puks.get_key_by_kid(1)
puks.get_key_by_uid("1")

prks.get_key_by_kid(1)
prks.get_key_by_uid("1")

print("End Hello world")