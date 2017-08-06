from .constants import MAX_PROTOCOL_NAME_LEN


class NoiseProtocol(object):
    def __init__(self, protocol_name: bytes):
        if len(protocol_name) > MAX_PROTOCOL_NAME_LEN:
            raise Exception('Protocol name too long, has to be at most {} chars long'.format(MAX_PROTOCOL_NAME_LEN))

        self.pattern = None
        self.pattern_modifiers = None
        self.dh = None
        self.dh_modifiers = None
        self.cipher = None
        self.cipher_modifiers = None
        self.hash = None
        self.hash_modifiers = None


class KeyPair(object):
    def __init__(self, public='', private=''):
        # TODO: Maybe switch to properties?
        self.public = public
        self.private = private
