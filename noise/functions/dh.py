import abc


class DH(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def klass(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def dhlen(self):
        raise NotImplementedError

    @abc.abstractmethod
    def generate_keypair(self) -> 'KeyPair':
        raise NotImplementedError

    @abc.abstractmethod
    def dh(self, private_key, public_key) -> bytes:
        raise NotImplementedError
