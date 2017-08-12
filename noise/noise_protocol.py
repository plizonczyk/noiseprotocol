from functools import partial
from typing import Tuple

from .patterns import patterns_map
from .constants import MAX_PROTOCOL_NAME_LEN
from .crypto import ed448

from Crypto.Cipher import AES, ChaCha20
from Crypto.Hash import BLAKE2b, BLAKE2s, SHA256, SHA512
import ed25519


dh_map = {
    '25519': ed25519.create_keypair,
    '448': ed448  # TODO implement
}

cipher_map = {
    'AESGCM': partial(AES.new, mode=AES.MODE_GCM),
    'ChaChaPoly': lambda key: ChaCha20.new(key=key)
}

hash_map = {
    # TODO benchmark vs hashlib implementation
    'BLAKE2b': BLAKE2b,  # TODO PARTIALS
    'BLAKE2s': BLAKE2s,  # TODO PARTIALS
    'SHA256': SHA256,  # TODO PARTIALS
    'SHA512': SHA512  # TODO PARTIALS
}


class NoiseProtocol(object):
    """
    TODO: Document
    """
    methods = {
        'pattern': patterns_map,
        'dh': dh_map,
        'cipher': cipher_map,
        'hash': hash_map
    }

    def __init__(self, protocol_name: bytes):
        if len(protocol_name) > MAX_PROTOCOL_NAME_LEN:
            raise ValueError('Protocol name too long, has to be at most {} chars long'.format(MAX_PROTOCOL_NAME_LEN))

        self.name = protocol_name
        mappings, pattern_modifiers = self._parse_protocol_name()

        self.pattern = mappings['pattern']()
        self.pattern_modifiers = pattern_modifiers
        if self.pattern_modifiers:
            self.pattern.apply_pattern_modifiers(pattern_modifiers)

        self.dh = mappings['pattern']
        self.cipher = mappings['pattern']
        self.hash = mappings['pattern']

    def _parse_protocol_name(self) -> Tuple[dict, list]:
        unpacked = self.name.split('_')
        if unpacked[0] != 'Noise':
            raise ValueError('Noise Protocol name shall begin with Noise! Provided: {}'.format(self.name))

        # Extract pattern name and pattern modifiers
        pattern = ''
        modifiers_str = None
        for i, char in enumerate(unpacked[1]):
            if char.isupper():
                pattern += char
            else:
                # End of pattern, now look for modifiers
                modifiers_str = unpacked[1][i:]  # Will be empty string if it exceeds string size
                break
        modifiers = modifiers_str.split('+') if modifiers_str else []

        data = {'pattern': 'Pattern' + pattern,
                'dh': unpacked[2],
                'cipher': unpacked[3],
                'hash': unpacked[4],
                'pattern_modifiers': modifiers}

        mapped_data = {}

        # Validate if we know everything that Noise Protocol is supposed to use and map appropriate functions
        for key, map_dict in self.methods.items():
            func = map_dict.get(data[key])
            if not func:
                raise ValueError('Unknown {} in Noise Protocol name, given {}, known {}'.format(
                    key, data[key], " ".join(map_dict)))
            mapped_data[key] = func

        return mapped_data, modifiers


class KeyPair(object):
    def __init__(self, public='', private=''):
        # TODO: Maybe switch to properties?
        self.public = public
        self.private = private
