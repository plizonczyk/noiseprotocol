class CipherState(object):
    """
    
    """
    def __init__(self):
        self.k = None
        self.n = None

    def initialize_key(self, key):
        """
        
        :param key: 
        :return: 
        """
        pass

    def has_key(self):
        """
        
        :return: 
        """
        return self.k is not None

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
        self.handshake_pattern = None
        self.initiator = None
        self.prologue = b''
        self.s = None
        self.e = None
        self.rs = None
        self.re = None

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
