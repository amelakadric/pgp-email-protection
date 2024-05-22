import key_store_interface as ksi
import PGPCore as pgpc

print("Interface test")


puks = ksi.PublicKeyStore()
prks = ksi.PrivateKeyStore()

puks.get_key_by_kid(1)
puks.get_key_by_uid("1")

prks.get_key_by_kid(1, "a")
prks.get_key_by_uid("1", "a")

print("End Interface test")


print("PGPCore test")

pgp1 = pgpc.PGPCore(1, 2, "hello hello this is test of aes128")
pgp1.aes128() # set symmetric algorithm we want to use
print(pgp1.encrypt().get_data())
print(pgp1.decrypt().get_data())

print()

pgp2 = pgpc.PGPCore(3, 4, "This message is to test functioning of 3des algorithm")
pgp2.tripple_des() # set symmetric algorithm we want to use
print(pgp2.encrypt().get_data())
print(pgp2.decrypt().get_data())

print("END PGPCore test")