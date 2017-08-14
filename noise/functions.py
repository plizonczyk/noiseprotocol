from .crypto import ed448

from Crypto.Cipher import AES, ChaCha20
from Crypto.Hash import BLAKE2b, BLAKE2s, SHA256, SHA512
import ed25519


dh_map = {
    '25519': ed25519,
    '448': ed448  # TODO implement
}

cipher_map = {
    'AESGCM': AES,
    'ChaChaPoly': ChaCha20
}

hash_map = {
    # TODO benchmark pycryptodome vs hashlib implementation
    'BLAKE2b': BLAKE2b,
    'BLAKE2s': BLAKE2s,
    'SHA256': SHA256,
    'SHA512': SHA512
}


class DH(object):
    def __init__(self, method):
        self.method = method
        self.dhlen = 0
        self.dh = None

    def generate_keypair(self) -> 'KeyPair':
        pass


class Cipher(object):
    def __init__(self, method):
        pass

    def encrypt(self, k, n, ad, plaintext):
        pass

    def decrypt(self, k, n, ad, ciphertext):
        pass


class Hash(object):
    def __init__(self, method):
        self.hashlen = 0
        self.blocklen = 0

    def hash(self):
        pass


class KeyPair(object):
    def __init__(self, public='', private=''):
        # TODO: Maybe switch to properties?
        self.public = public
        self.private = private
        if private and not public:
            self.derive_public_key()

    def derive_public_key(self):
        pass
