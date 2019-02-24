from typing import Union

from noise.exceptions import NoiseMaxNonceError
from .constants import Empty, TOKEN_E, TOKEN_S, TOKEN_EE, TOKEN_ES, TOKEN_SE, TOKEN_SS, TOKEN_PSK, MAX_NONCE


class CipherState(object):
    """
    Implemented as per Noise Protocol specification - paragraph 5.1.

    The initialize_key() function takes additional required argument - noise_protocol.

    This class holds an instance of Cipher wrapper. It manages initialisation of underlying cipher function
    with appropriate key in initialize_key() and rekey() methods.
    """
    def __init__(self, noise_protocol):
        self.k = Empty()
        self.n = None
        self.cipher = noise_protocol.cipher_class()

    def initialize_key(self, key):
        """

        :param key: Key to set within CipherState
        """
        self.k = key
        self.n = 0
        if self.has_key():
            self.cipher.initialize(key)

    def has_key(self):
        """

        :return: True if self.k is not an instance of Empty
        """
        return not isinstance(self.k, Empty)

    def set_nonce(self, nonce):
        self.n = nonce

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        """
        If k is non-empty returns ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.

        :param ad: bytes sequence
        :param plaintext: bytes sequence
        :return: ciphertext bytes sequence
        """
        if self.n == MAX_NONCE:
            raise NoiseMaxNonceError('Nonce has depleted!')

        if not self.has_key():
            return plaintext

        ciphertext = self.cipher.encrypt(self.k, self.n, ad, plaintext)
        self.n = self.n + 1
        return ciphertext

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        """
        If k is non-empty returns DECRYPT(k, n++, ad, ciphertext). Otherwise returns ciphertext. If an authentication
        failure occurs in DECRYPT() then n is not incremented and an error is signaled to the caller.

        :param ad: bytes sequence
        :param ciphertext: bytes sequence
        :return: plaintext bytes sequence
        """
        if self.n == MAX_NONCE:
            raise NoiseMaxNonceError('Nonce has depleted!')

        if not self.has_key():
            return ciphertext

        plaintext = self.cipher.decrypt(self.k, self.n, ad, ciphertext)
        self.n = self.n + 1
        return plaintext

    def rekey(self):
        self.k = self.cipher.rekey(self.k)
        self.cipher.initialize(self.k)


class SymmetricState(object):
    """
    Implemented as per Noise Protocol specification - paragraph 5.2.

    The initialize_symmetric function takes different required argument - noise_protocol, which contains protocol_name.
    """
    def __init__(self):
        self.h = None
        self.ck = None
        self.noise_protocol = None
        self.cipher_state = None

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

        # If protocol_name is less than or equal to HASHLEN bytes in length, sets h equal to protocol_name with zero
        # bytes appended to make HASHLEN bytes. Otherwise sets h = HASH(protocol_name).
        if len(noise_protocol.name) <= noise_protocol.hash_fn.hashlen:
            instance.h = noise_protocol.name.ljust(noise_protocol.hash_fn.hashlen, b'\0')
        else:
            instance.h = noise_protocol.hash_fn.hash(noise_protocol.name)

        # Sets ck = h.
        instance.ck = instance.h

        # Calls InitializeKey(empty).
        instance.cipher_state = CipherState(noise_protocol)
        instance.cipher_state.initialize_key(Empty())
        noise_protocol.cipher_state_handshake = instance.cipher_state

        return instance

    def mix_key(self, input_key_material: bytes):
        """

        :param input_key_material: 
        :return: 
        """
        # Sets ck, temp_k = HKDF(ck, input_key_material, 2).
        self.ck, temp_k = self.noise_protocol.hkdf(self.ck, input_key_material, 2)
        # If HASHLEN is 64, then truncates temp_k to 32 bytes.
        if self.noise_protocol.hash_fn.hashlen == 64:
            temp_k = temp_k[:32]

        # Calls InitializeKey(temp_k).
        self.cipher_state.initialize_key(temp_k)

    def mix_hash(self, data: bytes):
        """
        Sets h = HASH(h + data).

        :param data: bytes sequence
        """
        self.h = self.noise_protocol.hash_fn.hash(self.h + data)

    def mix_key_and_hash(self, input_key_material: bytes):
        # Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
        self.ck, temp_h, temp_k = self.noise_protocol.hkdf(self.ck, input_key_material, 3)
        # Calls MixHash(temp_h).
        self.mix_hash(temp_h)
        # If HASHLEN is 64, then truncates temp_k to 32 bytes.
        if self.noise_protocol.hash_fn.hashlen == 64:
            temp_k = temp_k[:32]
        # Calls InitializeKey(temp_k).
        self.cipher_state.initialize_key(temp_k)

    def get_handshake_hash(self):
        return self.h

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """
        Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. Note that if
        k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.

        :param plaintext: bytes sequence
        :return: ciphertext bytes sequence
        """
        ciphertext = self.cipher_state.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        """
        Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext. Note that if
        k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.

        :param ciphertext: bytes sequence
        :return: plaintext bytes sequence
        """
        plaintext = self.cipher_state.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self):
        """
        Returns a pair of CipherState objects for encrypting/decrypting transport messages.

        :return: tuple (CipherState, CipherState)
        """
        # Sets temp_k1, temp_k2 = HKDF(ck, b'', 2).
        temp_k1, temp_k2 = self.noise_protocol.hkdf(self.ck, b'', 2)

        # If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
        if self.noise_protocol.hash_fn.hashlen == 64:
            temp_k1 = temp_k1[:32]
            temp_k2 = temp_k2[:32]

        # Creates two new CipherState objects c1 and c2.
        # Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
        c1, c2 = CipherState(self.noise_protocol), CipherState(self.noise_protocol)
        c1.initialize_key(temp_k1)
        c2.initialize_key(temp_k2)
        if self.noise_protocol.handshake_state.initiator:
            self.noise_protocol.cipher_state_encrypt = c1
            self.noise_protocol.cipher_state_decrypt = c2
        else:
            self.noise_protocol.cipher_state_encrypt = c2
            self.noise_protocol.cipher_state_decrypt = c1

        self.noise_protocol.handshake_done()

        # Returns the pair (c1, c2).
        return c1, c2


class HandshakeState(object):
    """
    Implemented as per Noise Protocol specification - paragraph 5.3.

    The initialize() function takes different required argument - noise_protocol, which contains handshake_pattern.
    """
    def __init__(self):
        self.noise_protocol = None
        self.symmetric_state = None
        self.initiator = None
        self.s = None
        self.e = None
        self.rs = None
        self.re = None
        self.message_patterns = None

    @classmethod
    def initialize(cls, noise_protocol: 'NoiseProtocol', initiator: bool, prologue: bytes=b'', s: '_KeyPair'=None,
                   e: '_KeyPair'=None, rs: '_KeyPair'=None, re: '_KeyPair'=None) -> 'HandshakeState':
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
            instance.symmetric_state.mix_hash(keypair.public_bytes)
        for keypair in map(responder_keypair_getter, noise_protocol.pattern.get_responder_pre_messages()):
            instance.symmetric_state.mix_hash(keypair.public_bytes)

        # Sets message_patterns to the message patterns from handshake_pattern
        instance.message_patterns = noise_protocol.pattern.tokens.copy()

        return instance

    def write_message(self, payload: Union[bytes, bytearray], message_buffer: bytearray):
        """
        Comments below are mostly copied from specification.

        :param payload: byte sequence which may be zero-length
        :param message_buffer: buffer-like object
        :return: None or result of SymmetricState.split() - tuple (CipherState, CipherState)
        """
        # Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token
        # from the message pattern
        message_pattern = self.message_patterns.pop(0)
        for token in message_pattern:
            if token == TOKEN_E:
                # Sets e = GENERATE_KEYPAIR(). Appends e.public_key to the buffer. Calls MixHash(e.public_key)
                self.e = self.noise_protocol.dh_fn.generate_keypair() if isinstance(self.e, Empty) else self.e
                message_buffer += self.e.public_bytes
                self.symmetric_state.mix_hash(self.e.public_bytes)
                if self.noise_protocol.is_psk_handshake:
                    self.symmetric_state.mix_key(self.e.public_bytes)

            elif token == TOKEN_S:
                # Appends EncryptAndHash(s.public_key) to the buffer
                message_buffer += self.symmetric_state.encrypt_and_hash(self.s.public_bytes)

            elif token == TOKEN_EE:
                # Calls MixKey(DH(e, re))
                self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.e.private, self.re.public))

            elif token == TOKEN_ES:
                # Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.e.private, self.rs.public))
                else:
                    self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.s.private, self.re.public))

            elif token == TOKEN_SE:
                # Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.s.private, self.re.public))
                else:
                    self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.e.private, self.rs.public))

            elif token == TOKEN_SS:
                # Calls MixKey(DH(s, rs))
                self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.s.private, self.rs.public))

            elif token == TOKEN_PSK:
                self.symmetric_state.mix_key_and_hash(self.noise_protocol.psks.pop(0))

            else:
                raise NotImplementedError('Pattern token: {}'.format(token))

        # Appends EncryptAndHash(payload) to the buffer
        message_buffer += self.symmetric_state.encrypt_and_hash(payload)

        # If there are no more message patterns returns two new CipherState objects by calling Split()
        if len(self.message_patterns) == 0:
            return self.symmetric_state.split()

    def read_message(self, message: Union[bytes, bytearray], payload_buffer: bytearray):
        """
        Comments below are mostly copied from specification.

        :param message: byte sequence containing a Noise handshake message
        :param payload_buffer: buffer-like object
        :return: None or result of SymmetricState.split() - tuple (CipherState, CipherState)
        """
        # Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token
        # from the message pattern
        dhlen = self.noise_protocol.dh_fn.dhlen
        message_pattern = self.message_patterns.pop(0)
        for token in message_pattern:
            if token == TOKEN_E:
                # Sets re to the next DHLEN bytes from the message. Calls MixHash(re.public_key).
                self.re = self.noise_protocol.keypair_class.from_public_bytes(bytes(message[:dhlen]))
                message = message[dhlen:]
                self.symmetric_state.mix_hash(self.re.public_bytes)
                if self.noise_protocol.is_psk_handshake:
                    self.symmetric_state.mix_key(self.re.public_bytes)

            elif token == TOKEN_S:
                # Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True, or to the next DHLEN bytes
                # otherwise. Sets rs to DecryptAndHash(temp).
                if self.noise_protocol.cipher_state_handshake.has_key():
                    temp = bytes(message[:dhlen + 16])
                    message = message[dhlen + 16:]
                else:
                    temp = bytes(message[:dhlen])
                    message = message[dhlen:]
                self.rs = self.noise_protocol.keypair_class.from_public_bytes(
                    self.symmetric_state.decrypt_and_hash(temp)
                )

            elif token == TOKEN_EE:
                # Calls MixKey(DH(e, re)).
                self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.e.private, self.re.public))

            elif token == TOKEN_ES:
                # Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.e.private, self.rs.public))
                else:
                    self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.s.private, self.re.public))

            elif token == TOKEN_SE:
                # Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.s.private, self.re.public))
                else:
                    self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.e.private, self.rs.public))

            elif token == TOKEN_SS:
                # Calls MixKey(DH(s, rs))
                self.symmetric_state.mix_key(self.noise_protocol.dh_fn.dh(self.s.private, self.rs.public))

            elif token == TOKEN_PSK:
                self.symmetric_state.mix_key_and_hash(self.noise_protocol.psks.pop(0))

            else:
                raise NotImplementedError('Pattern token: {}'.format(token))

        # Calls DecryptAndHash() on the remaining bytes of the message and stores the output into payload_buffer.
        payload_buffer += self.symmetric_state.decrypt_and_hash(bytes(message))

        # If there are no more message patterns returns two new CipherState objects by calling Split()
        if len(self.message_patterns) == 0:
            return self.symmetric_state.split()

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
