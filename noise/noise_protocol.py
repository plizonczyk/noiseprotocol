from functools import partial

from .patterns import patterns_map
from .constants import MAX_PROTOCOL_NAME_LEN
from Crypto.Cipher import AES, ChaCha20
from Crypto.Hash import BLAKE2b, BLAKE2s, SHA256, SHA512
import ed25519

dh_map = {
    '25519': ed25519.create_keypair,
    '448': None  # TODO implement
}

cipher_map = {
    'AESGCM': partial(AES.new, mode=AES.MODE_GCM),
    'ChaChaPoly': lambda key: ChaCha20.new(key=key)
}

hash_map = {
    'BLAKE2b': BLAKE2b,  # TODO PARTIALS
    'BLAKE2s': BLAKE2s,  # TODO PARTIALS
    'SHA256': SHA256,  # TODO PARTIALS
    'SHA512': SHA512  # TODO PARTIALS
}


class NoiseProtocol(object):
    methods = {
        'pattern': patterns_map,
        'dh': dh_map,

    }
    def __init__(self, protocol_name: bytes):
        if len(protocol_name) > MAX_PROTOCOL_NAME_LEN:
            raise ValueError('Protocol name too long, has to be at most {} chars long'.format(MAX_PROTOCOL_NAME_LEN))

        self.name = protocol_name
        data_dict = self._split_protocol_name()
        self.pattern = patterns_map[data_dict['pattern']]
        self.pattern_modifiers = None
        self.dh = None
        self.cipher = None
        self.hash = None

    def _split_protocol_name(self):
        unpacked = self.name.split('_')
        if unpacked[0] != 'Noise':
            raise ValueError(f'Noise protocol name shall begin with Noise! Provided: {self.name}')

        pattern = ''
        modifiers_str = None
        for i, char in enumerate(unpacked[1]):
            if char.isupper():
                pattern += char
            else:
                modifiers_str = unpacked[1][i+1:]  # Will be empty string if it exceeds string size
                break
        modifiers = modifiers_str.split('+') if modifiers_str else []

        data = {'pattern': 'Pattern' + pattern,
                'dh': unpacked[2],
                'cipher': unpacked[3],
                'hash': unpacked[4],
                'pattern_modifiers': modifiers}

        # Validate if we know everything that Noise Protocol is supposed to use
        # TODO validation

        return data


class KeyPair(object):
    def __init__(self, public='', private=''):
        # TODO: Maybe switch to properties?
        self.public = public
        self.private = private
