from .constants import Empty


class CipherState(object):
    """
    Implemented as per Noise Protocol specification (rev 32) - paragraph 5.1.

    The initialize_key() function takes additional required argument - noise_protocol.
    """
    def __init__(self):
        self.k = Empty()
        self.n = None
        self.noise_protocol = None

    @classmethod
    def initialize_key(cls, key, noise_protocol: 'NoiseProtocol') -> 'CipherState':
        """

        :param key:
        :param noise_protocol: a valid NoiseProtocol instance
        :return: initialised CipherState instance
        """
        instance = cls()
        instance.noise_protocol = noise_protocol
        noise_protocol.cipher_state = instance

        instance.k = key
        instance.n = 0
        return instance

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
    Implemented as per Noise Protocol specification (rev 32) - paragraph 5.2.

    The initialize_symmetric function takes different required argument - noise_protocol, which contains protocol_name.
    """
    def __init__(self):
        self.h = None
        self.ck = None
        self.noise_protocol = None

    @classmethod
    def initialize_symmetric(cls, noise_protocol: 'NoiseProtocol') -> 'SymmetricState':
        """
        Instead of taking protocol_name as an argument, we take full NoiseProtocol object, that way we have access to
        protocol name and crypto functions

        Comments below are mostly copied from specification.
        :param noise_protocol: a valid NoiseProtocol instance
        :return: initialised SymmetricState instance
        """
        # Create SymmetricState
        instance = cls()
        instance.noise_protocol = noise_protocol
        noise_protocol.symmetric_state = instance

        # If protocol_name is less than or equal to HASHLEN bytes in length, sets h equal to protocol_name with zero
        # bytes appended to make HASHLEN bytes. Otherwise sets h = HASH(protocol_name).
        if len(noise_protocol.name) <= noise_protocol.hash_fn.hashlen:
            instance.h = noise_protocol.name.ljust(noise_protocol.hash_fn.hashlen, b'\0')
        else:
            instance.h = noise_protocol.hash_fn.hash(noise_protocol.name)

        # Sets ck = h.
        instance.ck = instance.h

        # Calls InitializeKey(empty).
        CipherState.initialize_key(Empty(), noise_protocol)

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
        self.h = self.noise_protocol.hash_fn.hash(data + self.h)

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

    The initialize() function takes different required argument - noise_protocol, which contains handshake_pattern.
    """
    @classmethod
    def initialize(cls, noise_protocol: 'NoiseProtocol', initiator: bool, prologue: bytes=b'', s: bytes=None,
                   e: bytes=None, rs: bytes=None, re: bytes=None) -> 'HandshakeState':
        """
        Constructor method.
        Comments below are mostly copied from specification.
        Instead of taking handshake_pattern as an argument, we take full NoiseProtocol object, that way we have access
        to protocol name and crypto functions

        :param noise_protocol: a valid NoiseProtocol instance
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
        instance.noise_protocol = noise_protocol
        noise_protocol.handshake_state = instance

        # Originally in specification:
        # "Derives a protocol_name byte sequence by combining the names for
        # the handshake pattern and crypto functions, as specified in Section 8."
        # Instead, we supply the NoiseProtocol to the function. The protocol name should already be validated.

        # Calls InitializeSymmetric(noise_protocol)
        instance.symmetric_state = SymmetricState.initialize_symmetric(noise_protocol)

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
        initiator_keypair_getter = instance._get_local_keypair if initiator else instance._get_remote_keypair
        responder_keypair_getter = instance._get_remote_keypair if initiator else instance._get_local_keypair
        for keypair in map(initiator_keypair_getter, noise_protocol.pattern.get_initiator_pre_messages()):
            instance.symmetric_state.mix_hash(keypair.public)
        for keypair in map(responder_keypair_getter, noise_protocol.pattern.get_responder_pre_messages()):
            instance.symmetric_state.mix_hash(keypair.public)

        # Sets message_patterns to the message patterns from handshake_pattern
        instance.message_patterns = noise_protocol.pattern.tokens

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
