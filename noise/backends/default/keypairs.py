import os
import warnings

from cryptography.hazmat.primitives.asymmetric import x25519

from noise.backends.default.crypto import X448
from noise.exceptions import NoiseValueError
from noise.functions.keypair import KeyPair


class KeyPair25519(KeyPair):
    @classmethod
    def from_private_bytes(cls, private_bytes):
        if len(private_bytes) != 32:
            raise NoiseValueError('Invalid length of private_bytes! Should be 32')
        private = x25519.X25519PrivateKey._from_private_bytes(private_bytes)
        public = private.public_key()
        return cls(private=private, public=public, public_bytes=public.public_bytes())

    @classmethod
    def from_public_bytes(cls, public_bytes):
        if len(public_bytes) != 32:
            raise NoiseValueError('Invalid length of public_bytes! Should be 32')
        public = x25519.X25519PublicKey.from_public_bytes(public_bytes)
        return cls(public=public, public_bytes=public.public_bytes())


class KeyPair448(KeyPair):
    def __init__(self, *args, **kwargs):
        super(KeyPair448, self).__init__(*args, **kwargs)
        warnings.warn('This implementation of ed448 is likely to be very insecure! USE ONLY FOR TESTING!')

    @classmethod
    def from_private_bytes(cls, private_bytes):
        if len(private_bytes) != 56:
            raise NoiseValueError('Invalid length of private_bytes! Should be 56')
        private = private_bytes
        public = X448.mul_5(private)
        return cls(private=private, public=public, public_bytes=public)

    @classmethod
    def from_public_bytes(cls, public_bytes):
        if len(public_bytes) != 56:
            raise NoiseValueError('Invalid length of private_bytes! Should be 56')
        return cls(public=public_bytes, public_bytes=public_bytes)

    @classmethod
    def new(cls):
        private = os.urandom(56)
        public = X448.mul_5(private)
        return cls(private=private, public=public, public_bytes=public)
