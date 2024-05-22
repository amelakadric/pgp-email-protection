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

pgp3 = pgpc.PGPCore(5, 6, b"message for testing sha1 message digest")
print(pgp3.sha1().signature)
pgp3.write_data_to_tmp()
pgp3.read_data_from_temp()

print(pgp3.zip().unzip().get_data())

pgp4 = pgpc.PGPCore(7, 8, "this is some message, for testing writing data to file")
print(pgp4)
# test printing string data to file
#pgp4.write_data_to_tmp()
print(pgp4.get_data())
pgp4.aes128().encrypt()
print(pgp4.get_data())
# test printing byte data to file
pgp4.write_data_to_tmp()
print("file data:")
with open("temp_data.txt", "rb") as f:
    print(f.read())

print("END PGPCore test")