from .crypto import ed448

from Crypto.Cipher import AES, ChaCha20
from Crypto.Hash import BLAKE2b, BLAKE2s, SHA256, SHA512
import ed25519


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
        if method == 'SHA256':
            self.hashlen = 32
            self.blocklen = 64
            self.hash = self._hash_sha256
        elif method == 'SHA512':
            self.hashlen = 64
            self.blocklen = 128
            self.hash = self._hash_sha512
        elif method == 'BLAKE2s':
            self.hashlen = 32
            self.blocklen = 64
            self.hash = self._hash_blake2s
        elif method == 'BLAKE2b':
            self.hashlen = 64
            self.blocklen = 128
            self.hash = self._hash_blake2b

    def _hash_sha256(self, data):
        return SHA256.new(data).digest()

    def _hash_sha512(self, data):
        return SHA512.new(data).digest()

    def _hash_blake2s(self, data):
        return BLAKE2s.new(data=data, digest_bytes=self.hashlen).digest()

    def _hash_blake2b(self, data):
        return BLAKE2b.new(data=data, digest_bytes=self.hashlen).digest()


class KeyPair(object):
    def __init__(self, public=b'', private=b''):
        # TODO: Maybe switch to properties?
        self.public = public
        self.private = private
        if private and not public:
            self.derive_public_key()

    def derive_public_key(self):
        pass


# Available crypto functions
# TODO: Check if it's safe to use one instance globally per cryptoalgorithm - i.e. if wrapper only provides interface
# If not - switch to partials(?)
dh_map = {
    '25519': DH('ed25519'),
    '448': DH('ed448')
}

cipher_map = {
    'AESGCM': Cipher('AESGCM'),
    'ChaChaPoly': Cipher('ChaCha20')
}

hash_map = {
    # TODO benchmark pycryptodome vs hashlib implementation
    'BLAKE2s': Hash('BLAKE2s'),
    'BLAKE2b': Hash('BLAKE2b'),
    'SHA256': Hash('SHA256'),
    'SHA512': Hash('SHA512')
}
