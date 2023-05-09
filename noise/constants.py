class Empty:
    pass


# Handshake pattern tokens
TOKEN_E = 'e'
TOKEN_S = 's'
TOKEN_EE = 'ee'
TOKEN_ES = 'es'
TOKEN_SE = 'se'
TOKEN_SS = 'ss'
TOKEN_PSK = 'psk'


# In bytes, as in Section 8 of specification (rev 32)
MAX_PROTOCOL_NAME_LEN = 255

MAX_MESSAGE_LEN = 65535
# encryption adds 16 bytes of authentication data
MAX_PLAINTEXT_LEN = 65535 - 16

MAX_NONCE = 2 ** 64 - 1
