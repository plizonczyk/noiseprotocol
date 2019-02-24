import abc

from noise.constants import MAX_NONCE


class Cipher(metaclass=abc.ABCMeta):
    def __init__(self):
        self.cipher = None

    @property
    @abc.abstractmethod
    def klass(self):
        raise NotImplementedError

    @abc.abstractmethod
    def encrypt(self, k, n, ad, plaintext):
        raise NotImplementedError

    @abc.abstractmethod
    def decrypt(self, k, n, ad, ciphertext):
        raise NotImplementedError

    def rekey(self, k):
        return self.encrypt(k, MAX_NONCE, b'', b'\x00' * 32)[:32]

    def initialize(self, key):
        self.cipher = self.klass(key)
