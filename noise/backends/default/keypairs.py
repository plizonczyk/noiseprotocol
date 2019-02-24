from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, x448

from noise.exceptions import NoiseValueError
from noise.functions.keypair import KeyPair


class KeyPair25519(KeyPair):
    @classmethod
    def from_private_bytes(cls, private_bytes):
        if len(private_bytes) != 32:
            raise NoiseValueError('Invalid length of private_bytes! Should be 32')
        private = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        public = private.public_key()
        return cls(private=private, public=public, public_bytes=public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))

    @classmethod
    def from_public_bytes(cls, public_bytes):
        if len(public_bytes) != 32:
            raise NoiseValueError('Invalid length of public_bytes! Should be 32')
        public = x25519.X25519PublicKey.from_public_bytes(public_bytes)
        return cls(public=public, public_bytes=public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))


class KeyPair448(KeyPair):
    @classmethod
    def from_private_bytes(cls, private_bytes):
        if len(private_bytes) != 56:
            raise NoiseValueError('Invalid length of private_bytes! Should be 56')
        private = x448.X448PrivateKey.from_private_bytes(private_bytes)
        public = private.public_key()
        return cls(private=private, public=public, public_bytes=public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))

    @classmethod
    def from_public_bytes(cls, public_bytes):
        if len(public_bytes) != 56:
            raise NoiseValueError('Invalid length of private_bytes! Should be 56')
        public = x448.X448PublicKey.from_public_bytes(public_bytes)
        return cls(public=public, public_bytes=public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
