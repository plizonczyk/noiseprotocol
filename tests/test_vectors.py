import io
import json
import logging
import os

import pytest

from noise.functions import KeyPair25519
from noise.state import HandshakeState, CipherState
from noise.noise_protocol import NoiseProtocol

logger = logging.getLogger(__name__)

vector_files = [
    'vectors/cacophony.txt',
    'vectors/noise-c-basic.txt'
]

# As in test vectors specification (https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors)
# We use this to cast read strings into bytes
byte_fields = ['protocol_name']
hexbyte_fields = ['init_prologue', 'init_static', 'init_ephemeral', 'init_remote_static', 'resp_static',
                  'resp_prologue', 'resp_ephemeral', 'resp_remote_static', 'handshake_hash']
list_fields = ['init_psks', 'resp_psks']
dict_field = 'messages'


def _prepare_test_vectors():
    vectors = []
    for path in vector_files:
        with open(os.path.join(os.path.dirname(__file__), path)) as fd:
            logging.info('Reading vectors from file {}'.format(path))
            vectors_list = json.load(fd)

        for vector in vectors_list:
            if 'name' in vector and not 'protocol_name' in vector:  # noise-c-* workaround
                vector['protocol_name'] = vector['name']
            if '_448_' in vector['protocol_name'] or 'psk' in vector['protocol_name'] or 'BLAKE' in vector['protocol_name'] or 'PSK' in vector['protocol_name']:
                continue  # TODO REMOVE WHEN ed448/psk/blake SUPPORT IS IMPLEMENTED/FIXED
            for key, value in vector.copy().items():
                if key in byte_fields:
                    vector[key] = value.encode()
                if key in hexbyte_fields:
                    vector[key] = bytes.fromhex(value)
                if key in list_fields:
                    vector[key] = [k.encode() for k in value]
                if key == dict_field:
                    vector[key] = []
                    for dictionary in value:
                        vector[key].append({k: bytes.fromhex(v) for k, v in dictionary.items()})
            vectors.append(vector)
    return vectors


def idfn(vector):
    return vector['protocol_name']


class TestVectors(object):
    @pytest.fixture(params=_prepare_test_vectors(), ids=idfn)
    def vector(self, request):
        yield request.param

    def _prepare_handshake_state_kwargs(self, vector):
        # TODO: This is ugly af, refactor it :/
        kwargs = {'init': {}, 'resp': {}}
        for role in ['init', 'resp']:
            for key, kwarg in [('static', 's'), ('ephemeral', 'e'), ('remote_static', 'rs')]:
                role_key = role + '_' + key
                if role_key in vector:
                    if key in ['static', 'ephemeral']:
                        kwargs[role][kwarg] = KeyPair25519.from_private_bytes(vector[role_key])  # TODO unify after adding 448
                    elif key == 'remote_static':
                        kwargs[role][kwarg] = KeyPair25519.from_public_bytes(vector[role_key])  # TODO unify after adding 448
        return kwargs

    def test_vector(self, vector):
        kwargs = self._prepare_handshake_state_kwargs(vector)

        init_protocol = NoiseProtocol(vector['protocol_name'])
        resp_protocol = NoiseProtocol(vector['protocol_name'])
        if 'init_psks' in vector and 'resp_psks' in vector:
            init_protocol.set_psks(vector['init_psks'])
            resp_protocol.set_psks(vector['resp_psks'])

        kwargs['init'].update(noise_protocol=init_protocol, initiator=True, prologue=vector['init_prologue'])
        kwargs['resp'].update(noise_protocol=resp_protocol, initiator=False, prologue=vector['resp_prologue'])

        initiator = HandshakeState.initialize(**kwargs['init'])
        responder = HandshakeState.initialize(**kwargs['resp'])
        initiator_to_responder = True

        handshake_finished = False
        for message in vector['messages']:
            if not handshake_finished:
                message_buffer = io.BytesIO()
                payload_buffer = io.BytesIO()
                if initiator_to_responder:
                    sender, receiver = initiator, responder
                else:
                    sender, receiver = responder, initiator

                sender_result = sender.write_message(message['payload'], message_buffer)
                assert message_buffer.getbuffer().tobytes() == message['ciphertext']

                message_buffer.seek(0)
                receiver_result = receiver.read_message(message_buffer, payload_buffer)
                assert payload_buffer.getbuffer().tobytes() == message['payload']

                if sender_result is None or receiver_result is None:
                    # Not finished with handshake, fail if one would finish before other
                    assert sender_result == receiver_result
                else:
                    # Handshake done
                    handshake_finished = True
                    assert isinstance(sender_result[0], CipherState)
                    assert isinstance(sender_result[1], CipherState)
                    assert isinstance(receiver_result[0], CipherState)
                    assert isinstance(receiver_result[1], CipherState)

                    # Verify handshake hash
                    assert init_protocol.symmetric_state.h == resp_protocol.symmetric_state.h == vector['handshake_hash']

                    # Verify split cipherstates keys
                    assert init_protocol.cipher_state_encrypt.k == resp_protocol.cipher_state_decrypt.k
                    if not init_protocol.pattern.one_way:
                        assert init_protocol.cipher_state_decrypt.k == resp_protocol.cipher_state_encrypt.k
            else:
                if init_protocol.pattern.one_way or initiator_to_responder:
                    sender, receiver = init_protocol, resp_protocol
                else:
                    sender, receiver = resp_protocol, init_protocol
                ciphertext = sender.cipher_state_encrypt.encrypt_with_ad(None, message['payload'])
                assert ciphertext == message['ciphertext']
                plaintext = receiver.cipher_state_decrypt.decrypt_with_ad(None, message['ciphertext'])
                assert plaintext == message['payload']
            initiator_to_responder = not initiator_to_responder
