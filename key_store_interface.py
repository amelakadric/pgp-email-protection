class PublicKeyStore():

    def __init__(self): pass

    # keyId = PU % (2 ** 64)
    # keyId is lower 64 bits of public key as int
    def get_key_by_kid(self, keyId : int) -> int: pass
        # returns public key as int
    
    # accepts userId (type str), usualy e-mail addr
    # associated with this user's public key
    def get_key_by_uid(self, userId : str) -> int: pass
        # returns public key as int


class PrivateKeyStore():

    def __init__(self): pass

    # keyId = PU % (2 ** 64) (type int)
    # is lower 64 bits of public key 
    # associated with wanted private key
    def get_key_by_kid(self, keyId : int) -> int: pass
        # returns private key as int

    # accepts userId (type str), usualy e-mail addr
    # associated with this private key
    # -- user can have more than one e-mail addr
    def get_key_by_uid(self, userId : str) -> int: pass
        # returns public key as int