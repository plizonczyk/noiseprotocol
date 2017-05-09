from noise.constants import Empty


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
    def __init__(self):
        self.ck = None
        self.h = None

    def initialize_symmetric(self, protocol_name):
        """
        
        :param protocol_name: 
        :return: 
        """
        pass

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
    
    """
    def __init__(self):
        self.symmetric_state = Empty()
        self.handshake_pattern = None
        self.initiator = None
        self.prologue = b''
        self.s = Empty()
        self.e = Empty()
        self.rs = Empty()
        self.re = Empty()

    def initialize(self, handshake_pattern, initiator, prologue=b'', s=None, e=None, rs=None, re=None):
        """
        
        :param handshake_pattern: 
        :param initiator: 
        :param prologue: 
        :param s: 
        :param e: 
        :param rs: 
        :param re: 
        :return: 
        """
        pass

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
