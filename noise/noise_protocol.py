from typing import Tuple

from .constants import MAX_PROTOCOL_NAME_LEN, Empty
from .functions import dh_map, cipher_map, hash_map
from .patterns import patterns_map


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
        if not isinstance(protocol_name, bytes):
            raise ValueError('Protocol name has to be of type "bytes", not {}'.format(type(protocol_name)))
        if len(protocol_name) > MAX_PROTOCOL_NAME_LEN:
            raise ValueError('Protocol name too long, has to be at most {} chars long'.format(MAX_PROTOCOL_NAME_LEN))

        self.name = protocol_name
        mappings, pattern_modifiers = self._parse_protocol_name()

        # A valid Pattern instance (see Section 7 of specification (rev 32))
        self.pattern = mappings['pattern']()
        self.pattern_modifiers = pattern_modifiers
        if self.pattern_modifiers:
            self.pattern.apply_pattern_modifiers(pattern_modifiers)

        self.dh_fn = mappings['dh']
        self.cipher_fn = mappings['cipher']
        self.hash_fn = mappings['hash']

        self.psks = None  # Placeholder for PSKs

        self.handshake_state = Empty()
        self.symmetric_state = Empty()
        self.cipher_state = Empty()

    def _parse_protocol_name(self) -> Tuple[dict, list]:
        unpacked = self.name.decode().split('_')
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

    def set_psks(self, psks: list) -> None:
        self.psks = psks
