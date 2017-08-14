import logging
import json
import os

import pytest

from noise.functions import KeyPair
from noise.state import HandshakeState
from noise.noise_protocol import NoiseProtocol

logger = logging.getLogger(__name__)

vector_files = ['vectors/cacophony.txt']

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
            if '_448_' in vector['protocol_name'] or 'ChaCha' in vector['protocol_name']:
                continue  # TODO REMOVE WHEN ed448/ChaCha SUPPORT IS IMPLEMENTED
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
                        vector[key].append({k: v.encode() for k, v in dictionary.items()})
            vectors.append(vector)
    return vectors


class TestVectors(object):
    @pytest.fixture(params=_prepare_test_vectors())
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
                        kwargs[role][kwarg] = KeyPair._25519_from_private_bytes(vector[role_key])  # TODO unify after adding 448
                    elif key == 'remote_static':
                        kwargs[role][kwarg] = KeyPair._25519_from_public_bytes(vector[role_key])  # TODO unify after adding 448
        return kwargs

    def test_vector(self, vector):
        logging.info('Testing vector {}'.format(vector['protocol_name']))

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
