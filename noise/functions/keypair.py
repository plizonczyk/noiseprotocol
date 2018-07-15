import abc


class KeyPair(metaclass=abc.ABCMeta):
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
