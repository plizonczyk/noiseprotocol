from .crypto import ed448

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519


class DH(object):
    def __init__(self, method):
        if method == 'ed25519':
            self.method = method
            self.dhlen = 32
            self.generate_keypair = self._25519_generate_keypair
            self.dh = self._25519_dh
        elif method == 'ed448':
            raise NotImplementedError
        else:
            raise NotImplementedError('DH method: {}'.format(method))

    def _25519_generate_keypair(self) -> 'KeyPair':
        private_key = x25519.X25519PrivateKey.generate()
        return KeyPair(private_key, private_key.public_key())

    def _25519_dh(self, keypair: 'x25519.X25519PrivateKey', public_key: 'x25519.X25519PublicKey') -> bytes:
        return keypair.exchange(public_key)


class Cipher(object):
    def __init__(self, method):
        if method == 'AESGCM':
            self._cipher = AESGCM
            self.encrypt = self._aesgcm_encrypt
            self.decrypt = self._aesgcm_decrypt
        elif method == 'ChaCha20':
            raise NotImplementedError
        else:
            raise NotImplementedError('Cipher method: {}'.format(method))

    def _aesgcm_encrypt(self, k, n, ad, plaintext):
        # Might be expensive to initialise AESGCM with the same key every time. The key should be (as per spec) kept in
        # CipherState, but we may as well hold an initialised AESGCM and manage reinitialisation on CipherState.rekey
        cipher = self._cipher(k)
        return cipher.encrypt(nonce=n, data=plaintext, associated_data=ad)

    def _aesgcm_decrypt(self, k, n, ad, ciphertext):
        cipher = self._cipher(k)
        return cipher.encrypt(nonce=n, data=ciphertext, associated_data=ad)


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
        else:
            raise NotImplementedError('Hash method: {}'.format(method))

    def _hash_sha256(self, data):
        digest = hashes.Hash(hashes.SHA256(), default_backend())
        digest.update(data)
        return digest.finalize()

    def _hash_sha512(self, data):
        digest = hashes.Hash(hashes.SHA512(), default_backend())
        digest.update(data)
        return digest.finalize()

    def _hash_blake2s(self, data):
        digest = hashes.Hash(hashes.BLAKE2s(digest_size=self.hashlen), default_backend())
        digest.update(data)
        return digest.finalize()

    def _hash_blake2b(self, data):
        digest = hashes.Hash(hashes.BLAKE2b(digest_size=self.hashlen), default_backend())
        digest.update(data)
        return digest.finalize()


class KeyPair(object):
    def __init__(self, private=None, public=None):
        self.private = private
        self.public = public

    @classmethod
    def _25519_from_private_bytes(cls, private_bytes):
        private = x25519.X25519PrivateKey._from_private_bytes(private_bytes)
        public = private.public_key().public_bytes()
        return cls(private=private, public=public)

    @classmethod
    def _25519_from_public_bytes(cls, public_bytes):
        return cls(public=x25519.X25519PublicKey.from_public_bytes(public_bytes).public_bytes())


# Available crypto functions
# TODO: Check if it's safe to use one instance globally per cryptoalgorithm - i.e. if wrapper only provides interface
# If not - switch to partials(?)
dh_map = {
    '25519': DH('ed25519'),
    # '448': DH('ed448')  # TODO uncomment when ed448 is implemented
}

cipher_map = {
    'AESGCM': Cipher('AESGCM'),
    # 'ChaChaPoly': Cipher('ChaCha20')  # TODO ugh cryptography lacks chacha primitive. use nacl I guess.
}

hash_map = {
    # TODO benchmark pycryptodome vs hashlib implementation
    'BLAKE2s': Hash('BLAKE2s'),
    'BLAKE2b': Hash('BLAKE2b'),
    'SHA256': Hash('SHA256'),
    'SHA512': Hash('SHA512')
}
