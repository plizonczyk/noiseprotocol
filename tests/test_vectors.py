import logging
import json
import os

import pytest

from noise.state import HandshakeState
from noise.noise_protocol import NoiseProtocol

logger = logging.getLogger(__name__)

vector_files = ['vectors/cacophony.txt']


def prepare_test_vectors():
    vectors = []
    for path in vector_files:
        with open(os.path.join(os.path.dirname(__file__), path)) as fd:
            logging.info(f'Reading vectors from file {path}')
            vectors.extend(json.load(fd))
    return vectors


@pytest.fixture(params=prepare_test_vectors())
def vector(request):
    yield request.param


def test_vector(vector):
    logging.info(f"Testing vector {vector['protocol_name']}")
    init_protocol = NoiseProtocol(vector['protocol_name'])
    resp_protocol = NoiseProtocol(vector['protocol_name'])
    initiator = HandshakeState.initialize(noise_protocol=init_protocol, handshake_pattern=init_protocol.pattern,
                                          initiator=True, prologue=vector['init_prologue'])
    responder = HandshakeState.initialize(noise_protocol=resp_protocol, handshake_pattern=resp_protocol.pattern,
                                          initiator=True, prologue=vector['resp_prologue'])
