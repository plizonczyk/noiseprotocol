import base64
import socket

import logging
import struct

import nacl

from constants import *

logger = logging.getLogger(__name__)


with open('../noise-keys/psk') as fd:
    psk = fd.readline()
    # psk = base64.b64decode(fd.readline())

protocol_id = struct.Struct('BBBBB')

noise_name = 'NoisePSK_NN_448_ChaChaPoly_BLAKE2b'
s = socket.socket()
s.connect(('localhost', 2000))


def get_packed_protocol_id(name):
    if not name.startswith('Noise'):
        logger.info('Wrong pattern: does not begin with "Noise"')
    name = name[5:]

    if name.startswith('PSK'):
        psk_byte = PSK.PSK_ENABLED.value
        name = name[3:]
    else:
        psk_byte = PSK.PSK_DISABLED.value
    name = name.lstrip('_')

    pattern = name[:2]
    pattern_byte = getattr(PATTERN, 'PATTERN_' + pattern).value

    name = name[2:].lstrip('_')

    dh = name.split('_')[0]
    dh_byte = getattr(DH, 'DH_' + dh).value
    name = name.lstrip(dh).lstrip('_')

    cipher = name.split('_')[0]
    cipher_byte = getattr(CIPHER, 'CIPHER_' + cipher.upper()).value
    name = name.lstrip(cipher).lstrip('_')

    hashing = name.split('_')[0]
    hashing_byte = getattr(HASH, 'HASH_' + hashing).value
    return protocol_id.pack(psk_byte, pattern_byte, cipher_byte, dh_byte, hashing_byte)

s.send(get_packed_protocol_id(noise_name))
s.send.

# import ipdb; ipdb.set_trace()
