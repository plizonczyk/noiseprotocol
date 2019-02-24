from noise.exceptions import NoiseProtocolNameError
from noise.functions.hash import hkdf
from noise.patterns import (PatternN, PatternK, PatternX, PatternNN, PatternKN, PatternNK, PatternKK, PatternNX,
                            PatternKX, PatternXN, PatternIN, PatternXK, PatternIK, PatternXX, PatternIX)


class NoiseBackend:
    """
    Base for creating backends.
    Implementing classes must define supported crypto methods in appropriate dict (diffie_hellmans, ciphers, etc.)
    HMAC function must be defined as well.

    Dicts use convention for keys - they must match the string that occurs in Noise Protocol name.
    """
    def __init__(self):
        self.patterns = {
            'N': PatternN,
            'K': PatternK,
            'X': PatternX,
            'NN': PatternNN,
            'KN': PatternKN,
            'NK': PatternNK,
            'KK': PatternKK,
            'NX': PatternNX,
            'KX': PatternKX,
            'XN': PatternXN,
            'IN': PatternIN,
            'XK': PatternXK,
            'IK': PatternIK,
            'XX': PatternXX,
            'IX': PatternIX,
        }

        self.diffie_hellmans = {}
        self.ciphers = {}
        self.hashes = {}
        self.keypairs = {}
        self.hmac = None

        self.hkdf = hkdf

    @property
    def methods(self):
        return {
            'pattern': self.patterns,
            'dh': self.diffie_hellmans,
            'cipher': self.ciphers,
            'hash': self.hashes,
            'keypair': self.keypairs
        }

    def map_protocol_name_to_crypto(self, unpacked_name):
        mappings = {}
        # Validate if we know everything that Noise Protocol is supposed to use and map appropriate functions
        for method, map_dict in self.methods.items():
            looked_up_func = getattr(unpacked_name, method)
            func = map_dict.get(looked_up_func)
            if not func:
                raise NoiseProtocolNameError('Unknown {} in Noise Protocol name, given {}, known {}'.format(
                                             method, looked_up_func, " ".join(map_dict)))
            mappings[method] = func

        return mappings

