import logging
import json
import os

import pytest

from noise.functions import KeyPair
from noise.state import HandshakeState
from noise.noise_protocol import NoiseProtocol

logger = logging.getLogger(__name__)

vector_files = ['vectors/cacophony.txt']


def _prepare_test_vectors():
    vectors = []
    for path in vector_files:
        with open(os.path.join(os.path.dirname(__file__), path)) as fd:
            logging.info('Reading vectors from file {}'.format(path))
            vectors.extend(json.load(fd))
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
                        kwargs[role][kwarg] = KeyPair(private=vector[role_key])
                    else:
                        kwargs[role][kwarg] = KeyPair(public=vector[role_key])
        return kwargs

    def test_vector(self, vector):
        logging.info('Testing vector {}'.format(vector['protocol_name']))

        kwargs = self._prepare_handshake_state_kwargs(vector)

        init_protocol = NoiseProtocol(vector['protocol_name'])
        resp_protocol = NoiseProtocol(vector['protocol_name'])
        if 'init_psks' in vector and 'resp_psks' in vector:
            init_protocol.set_psks(vector['init_psks'])
            resp_protocol.set_psks(vector['resp_psks'])

        kwargs['init'].update(noise_protocol=init_protocol, handshake_pattern=init_protocol.pattern, initiator=True,
                              prologue=vector['init_prologue'])
        kwargs['resp'].update(noise_protocol=resp_protocol, handshake_pattern=resp_protocol.pattern, initiator=False,
                              prologue=vector['resp_prologue'])

        initiator = HandshakeState.initialize(**kwargs['init'])
        responder = HandshakeState.initialize(**kwargs['resp'])
