from cryptography.hazmat.primitives.asymmetric import x25519, x448
from cryptography.hazmat.primitives import serialization

from noise.backends.default.keypairs import KeyPair25519, KeyPair448
from noise.exceptions import NoiseValueError
from noise.functions.dh import DH


class ED25519(DH):
    @property
    def klass(self):
        return KeyPair25519

    @property
    def dhlen(self):
        return 32

    def generate_keypair(self) -> 'KeyPair':
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair25519(private_key, public_key,
                            public_key.public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw))

    def dh(self, private_key, public_key) -> bytes:
        if not isinstance(private_key, x25519.X25519PrivateKey) or not isinstance(public_key, x25519.X25519PublicKey):
            raise NoiseValueError('Invalid keys! Must be x25519.X25519PrivateKey and x25519.X25519PublicKey instances')
        return private_key.exchange(public_key)


class ED448(DH):
    @property
    def klass(self):
        return KeyPair448

    @property
    def dhlen(self):
        return 56

    def generate_keypair(self) -> 'KeyPair':
        private_key = x448.X448PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair448(private_key, public_key,
                          public_key.public_bytes(serialization.Encoding.Raw,
                                                  serialization.PublicFormat.Raw))

    def dh(self, private_key, public_key) -> bytes:
        if not isinstance(private_key, x448.X448PrivateKey) or not isinstance(public_key, x448.X448PublicKey):
            raise NoiseValueError('Invalid keys! Must be x448.X448PrivateKey and x448.X448PublicKey instances')
        return private_key.exchange(public_key)
