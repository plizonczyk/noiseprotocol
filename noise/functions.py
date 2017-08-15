import abc
from functools import partial

from cryptography.hazmat.primitives.hmac import HMAC

from .crypto import ed448

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
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

    def _25519_generate_keypair(self) -> '_KeyPair':
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return _KeyPair(private_key, public_key, public_key.public_bytes())

    def _25519_dh(self, keypair: 'x25519.X25519PrivateKey', public_key: 'x25519.X25519PublicKey') -> bytes:
        return keypair.exchange(public_key)


class Cipher(object):
    def __init__(self, method):
        if method == 'AESGCM':
            self._cipher = AESGCM
            self.encrypt = self._aesgcm_encrypt
            self.decrypt = self._aesgcm_decrypt
        elif method == 'ChaCha20':
            self._cipher = ChaCha20Poly1305
            self.encrypt = self._chacha20_encrypt
            self.decrypt = self._chacha20_decrypt
        else:
            raise NotImplementedError('Cipher method: {}'.format(method))

    def _aesgcm_encrypt(self, k, n, ad, plaintext):
        # Might be expensive to initialise AESGCM with the same key every time. The key should be (as per spec) kept in
        # CipherState, but we may as well hold an initialised AESGCM and manage reinitialisation on CipherState.rekey
        cipher = self._cipher(k)
        return cipher.encrypt(nonce=self._aesgcm_nonce(n), data=plaintext, associated_data=ad)

    def _aesgcm_decrypt(self, k, n, ad, ciphertext):
        cipher = self._cipher(k)
        return cipher.decrypt(nonce=self._aesgcm_nonce(n), data=ciphertext, associated_data=ad)

    def _aesgcm_nonce(self, n):
        return b'\x00\x00\x00\x00' + n.to_bytes(length=8, byteorder='big')

    def _chacha20_encrypt(self, k, n, ad, plaintext):
        # Same comment as with AESGCM
        cipher = self._cipher(k)
        return cipher.encrypt(nonce=self._chacha20_nonce(n), data=plaintext, associated_data=ad)

    def _chacha20_decrypt(self, k, n, ad, ciphertext):
        cipher = self._cipher(k)
        return cipher.decrypt(nonce=self._chacha20_nonce(n), data=ciphertext, associated_data=ad)

    def _chacha20_nonce(self, n):
        return b'\x00\x00\x00\x00' + n.to_bytes(length=8, byteorder='little')


class Hash(object):
    def __init__(self, method):
        if method == 'SHA256':
            self.hashlen = 32
            self.blocklen = 64
            self.hash = self._hash_sha256
            self.fn = hashes.SHA256
        elif method == 'SHA512':
            self.hashlen = 64
            self.blocklen = 128
            self.hash = self._hash_sha512
            self.fn = hashes.SHA512
        elif method == 'BLAKE2s':
            self.hashlen = 32
            self.blocklen = 64
            self.hash = self._hash_blake2s
            self.fn = partial(hashes.BLAKE2s, digest_size=self.hashlen)
        elif method == 'BLAKE2b':
            self.hashlen = 64
            self.blocklen = 128
            self.hash = self._hash_blake2b
            self.fn = partial(hashes.BLAKE2b, digest_size=self.hashlen)
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


class _KeyPair(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, private=None, public=None, public_bytes=None):
        self.private = private
        self.public = public
        self.public_bytes = public_bytes

    @classmethod
    @abc.abstractmethod
    def from_private_bytes(cls, private_bytes):
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_public_bytes(cls, public_bytes):
        raise NotImplementedError


class KeyPair25519(_KeyPair):
    @classmethod
    def from_private_bytes(cls, private_bytes):
        private = x25519.X25519PrivateKey._from_private_bytes(private_bytes)
        public = private.public_key()
        return cls(private=private, public=public, public_bytes=public.public_bytes())

    @classmethod
    def from_public_bytes(cls, public_bytes):
        public = x25519.X25519PublicKey.from_public_bytes(public_bytes)
        return cls(public=public, public_bytes=public.public_bytes())


# Available crypto functions
# TODO: Check if it's safe to use one instance globally per cryptoalgorithm - i.e. if wrapper only provides interface
# If not - switch to partials(?)
dh_map = {
    '25519': DH('ed25519'),
    # '448': DH('ed448')  # TODO uncomment when ed448 is implemented
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

keypair_map = {
    '25519': KeyPair25519,
    # '448': DH('ed448')  # TODO uncomment when ed448 is implemented
}


def hmac_hash(key, data, algorithm):
    # Applies HMAC using the HASH() function.
    hmac = HMAC(key=key, algorithm=algorithm(), backend=default_backend())
    hmac.update(data=data)
    return hmac.finalize()


def hkdf(chaining_key, input_key_material, num_outputs, hmac_hash_fn):
    # Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
    temp_key = hmac_hash_fn(chaining_key, input_key_material)

    # Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
    output1 = hmac_hash_fn(temp_key, b'\x01')

    # Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
    output2 = hmac_hash_fn(temp_key, output1 + b'\x02')

    # If num_outputs == 2 then returns the pair (output1, output2).
    if num_outputs == 2:
        return output1, output2

    # Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
    output3 = hmac_hash_fn(temp_key, output2 + b'\x03')

    # Returns the triple (output1, output2, output3).
    return output1, output2, output3
