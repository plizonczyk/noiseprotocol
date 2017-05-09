from enum import Enum


class PSK(Enum):
    PSK_DISABLED = 0x00
    PSK_ENABLED = 0x01


class PATTERN(Enum):
    PATTERN_NN = 0x00
    PATTERN_KN = 0x01
    PATTERN_NK = 0x02
    PATTERN_KK = 0x03
    PATTERN_NX = 0x04
    PATTERN_KX = 0x05
    PATTERN_XN = 0x06
    PATTERN_IN = 0x07
    PATTERN_XK = 0x08
    PATTERN_IK = 0x09
    PATTERN_XX = 0x0A
    PATTERN_IX = 0x0B
    PATTERN_HFS = 0x80


class CIPHER(Enum):
    CIPHER_CHACHAPOLY = 0x00
    CIPHER_AESGCM = 0x01


class DH(Enum):
    DH_25519 = 0x00
    DH_448 = 0x01
    DH_NEWHOPE = 0x02
    DH_MASK = 0x0F


class HYBRID(Enum):
    HYBRID_NONE = 0x00
    HYBRID_25519 = 0x10
    HYBRID_448 = 0x20
    HYBRID_NEWHOPE = 0x30
    HYBRID_MASK = 0xF0


class HASH(Enum):
    HASH_SHA256 = 0x00
    HASH_SHA512 = 0x01
    HASH_BLAKE2s = 0x02
    HASH_BLAKE2b = 0x03