import json
import logging
import os

import pytest

from noise.connection import NoiseConnection, Keypair

logger = logging.getLogger(__name__)

vector_files = [
    'vectors/cacophony.txt',
    'vectors/snow-multipsk.txt'
]

# As in test vectors specification (https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors)
# We use this to cast read strings into bytes
byte_field = 'protocol_name'
hexbyte_fields = ('init_prologue', 'init_static', 'init_ephemeral', 'init_remote_static', 'resp_static',
                  'resp_prologue', 'resp_ephemeral', 'resp_remote_static', 'handshake_hash')
list_fields = ('init_psks', 'resp_psks')
dict_field = 'messages'


def _prepare_test_vectors():
    vectors = []
    for path in vector_files:
        with open(os.path.join(os.path.dirname(__file__), path)) as fd:
            logging.info('Reading vectors from file {}'.format(path))
            vectors_list = json.load(fd)

        for vector in vectors_list:
            for key, value in vector.copy().items():
                if key == byte_field:
                    vector[key] = value.encode()
                if key in hexbyte_fields:
                    vector[key] = bytes.fromhex(value)
                if key in list_fields:
                    vector[key] = [bytes.fromhex(k) for k in value]
                if key == dict_field:
                    vector[key] = []
                    for dictionary in value:
                        vector[key].append({k: bytes.fromhex(v) for k, v in dictionary.items()})
            vectors.append(vector)
    return vectors


def idfn(vector):
    return vector['protocol_name']


@pytest.mark.filterwarnings('ignore: This implementation of ed448')
@pytest.mark.filterwarnings('ignore: One of ephemeral keypairs')
class TestVectors(object):
    @pytest.fixture(params=_prepare_test_vectors(), ids=idfn)
    def vector(self, request):
        yield request.param

    def _set_keypairs(self, vector, connection):
        role = 'init' if connection.noise_protocol.initiator else 'resp'
        setters = [
            (connection.set_keypair_from_private_bytes, Keypair.STATIC, role + '_static'),
            (connection.set_keypair_from_private_bytes, Keypair.EPHEMERAL, role + '_ephemeral'),
            (connection.set_keypair_from_public_bytes, Keypair.REMOTE_STATIC, role + '_remote_static')
        ]
        for fn, keypair, name in setters:
            if name in vector:
                fn(keypair, vector[name])

    def test_vector(self, vector):
        initiator = NoiseConnection.from_name(vector['protocol_name'])
        responder = NoiseConnection.from_name(vector['protocol_name'])
        if 'init_psks' in vector and 'resp_psks' in vector:
            initiator.set_psks(psks=vector['init_psks'])
            responder.set_psks(psks=vector['resp_psks'])

        initiator.set_prologue(vector['init_prologue'])
        initiator.set_as_initiator()
        self._set_keypairs(vector, initiator)

        responder.set_prologue(vector['resp_prologue'])
        responder.set_as_responder()
        self._set_keypairs(vector, responder)

        initiator.start_handshake()
        responder.start_handshake()

        initiator_to_responder = True
        handshake_finished = False
        for message in vector['messages']:
            if not handshake_finished:
                if initiator_to_responder:
                    sender, receiver = initiator, responder
                else:
                    sender, receiver = responder, initiator

                sender_result = sender.write_message(message['payload'])
                assert sender_result == message['ciphertext']

                receiver_result = receiver.read_message(sender_result)
                assert receiver_result == message['payload']

                if not (sender.handshake_finished and receiver.handshake_finished):
                    # Not finished with handshake, fail if one would finish before other
                    assert sender.handshake_finished == receiver.handshake_finished
                else:
                    # Handshake done
                    handshake_finished = True

                    # Verify handshake hash
                    if 'handshake_hash' in vector:
                        assert initiator.noise_protocol.handshake_hash == responder.noise_protocol.handshake_hash == vector['handshake_hash']

                    # Verify split cipherstates keys
                    assert initiator.noise_protocol.cipher_state_encrypt.k == responder.noise_protocol.cipher_state_decrypt.k
                    if not initiator.noise_protocol.pattern.one_way:
                        assert initiator.noise_protocol.cipher_state_decrypt.k == responder.noise_protocol.cipher_state_encrypt.k
                    else:
                        assert initiator.noise_protocol.cipher_state_decrypt is responder.noise_protocol.cipher_state_encrypt is None
            else:
                if initiator.noise_protocol.pattern.one_way or initiator_to_responder:
                    sender, receiver = initiator, responder
                else:
                    sender, receiver = responder, initiator
                ciphertext = sender.encrypt(message['payload'])
                assert ciphertext == message['ciphertext']
                plaintext = receiver.decrypt(message['ciphertext'])
                assert plaintext == message['payload']
            initiator_to_responder = not initiator_to_responder
