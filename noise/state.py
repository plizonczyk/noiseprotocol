from .constants import Empty


class CipherState(object):
    """
    
    """
    def __init__(self):
        self.k = Empty()
        self.n = None

    def initialize_key(self, key):
        """

        :param key:
        :return: 
        """
        self.k = key
        self.n = 0

    def has_key(self):
        """
        
        :return: True if self.k is not an instance of Empty
        """
        return not isinstance(self.k, Empty)

    def encrypt_with_ad(self, ad, plaintext):
        """
        
        :param ad: 
        :param plaintext: 
        :return: 
        """
        pass

    def decrypt_with_ad(self, ad, plaintext):
        """
        
        :param ad: 
        :param plaintext: 
        :return: 
        """
        pass


class SymmetricState(object):
    """
    
    """
    @classmethod
    def initialize_symmetric(cls, protocol_name) -> 'SymmetricState':
        """
        
        :param protocol_name: 
        :return: 
        """
        instance = cls()
        # TODO
        return instance

    def mix_key(self, input_key_material):
        """
        
        :param input_key_material: 
        :return: 
        """

    def mix_hash(self, data):
        """
        
        :param data: 
        :return: 
        """

    def encrypt_and_hash(self, plaintext):
        """
        
        :param plaintext: 
        :return: 
        """
        pass

    def decrypt_and_hash(self, ciphertext):
        """
        
        :param ciphertext: 
        :return: 
        """
        pass

    def split(self):
        """
        
        :return: 
        """
        pass


class HandshakeState(object):
    """
    Implemented as per Noise Protocol specification (rev 32) - paragraph 5.3.

    The initialize() function takes additional required argument - protocol_name - to provide it to SymmetricState.
    """
    @classmethod
    def initialize(cls, handshake_pattern: 'Pattern', protocol_name: 'NoiseProtocol', initiator: bool,
                   prologue: bytes=b'', s: bytes=None, e: bytes=None, rs: bytes=None,
                   re: bytes=None) -> 'HandshakeState':
        """
        Constructor method.
        Comments below are mostly copied from specification.

        :param handshake_pattern: a valid Pattern instance (see Section 7 of specification (rev 32))
        :param protocol_name: a valid NoiseProtocol instance
        :param initiator: boolean indicating the initiator or responder role
        :param prologue: byte sequence which may be zero-length, or which may contain context information that both
        parties want to confirm is identical
        :param s: local static key pair
        :param e: local ephemeral key pair
        :param rs: remote party’s static public key
        :param re: remote party’s ephemeral public key
        :return: initialized HandshakeState instance
        """
        # Create HandshakeState
        instance = cls()

        # Originally in specification:
        # "Derives a protocol_name byte sequence by combining the names for
        # the handshake pattern and crypto functions, as specified in Section 8."
        # Instead, we supply the protocol name to the function. It should already be validated. We only check if the
        # handshake pattern specified as an argument is the same as in the protocol name

        # Calls InitializeSymmetric(protocol_name)
        instance.symmetric_state = SymmetricState.initialize_symmetric(protocol_name)

        # Calls MixHash(prologue)
        instance.symmetric_state.mix_hash(prologue)

        # Sets the initiator, s, e, rs, and re variables to the corresponding arguments
        instance.initiator = initiator
        instance.s = s if s is not None else Empty()
        instance.e = e if e is not None else Empty()
        instance.rs = rs if rs is not None else Empty()
        instance.re = re if re is not None else Empty()

        # Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern, with the specified
        # public key as input (...). If both initiator and responder have pre-messages, the initiator’s public keys are
        # hashed first
        for keypair in map(instance._get_local_keypair, handshake_pattern.get_initiator_pre_messages()):
            instance.symmetric_state.mix_hash(keypair.public)
        for keypair in map(instance._get_remote_keypair, handshake_pattern.get_responder_pre_messages()):
            instance.symmetric_state.mix_hash(keypair.public)

        # Sets message_patterns to the message patterns from handshake_pattern
        instance.message_patterns = handshake_pattern.tokens

        return instance

    def write_message(self, payload, message_buffer):
        """
        
        :param payload: 
        :param message_buffer: 
        :return: 
        """
        pass

    def read_message(self, message, payload_buffer):
        """
        
        :param message: 
        :param payload_buffer: 
        :return: 
        """
        pass

    def _get_local_keypair(self, token: str) -> 'KeyPair':
        keypair = getattr(self, token)  # Maybe explicitly handle exception when getting improper keypair
        if isinstance(keypair, Empty):
            raise Exception('Required keypair {} is empty!'.format(token))  # Maybe subclassed exception
        return keypair

    def _get_remote_keypair(self, token: str) -> 'KeyPair':
        keypair = getattr(self, 'r' + token)  # Maybe explicitly handle exception when getting improper keypair
        if isinstance(keypair, Empty):
            raise Exception('Required keypair {} is empty!'.format('r' + token))  # Maybe subclassed exception
        return keypair
