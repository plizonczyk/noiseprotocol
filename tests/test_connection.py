from noise.connection import NoiseConnection
import pytest


class TestConnection(object):
    def do_test_connection(self, name):
        key = b"\x00" * 32
        left = NoiseConnection.from_name(name)
        left.set_psks(key)
        left.set_as_initiator()
        left.start_handshake()

        right = NoiseConnection.from_name(name)
        right.set_psks(key)
        right.set_as_responder()
        right.start_handshake()

        h = left.write_message()
        _ = right.read_message(h)
        h2 = right.write_message()
        left.read_message(h2)

        assert left.handshake_finished
        assert right.handshake_finished

        enc = left.encrypt(b"hello")
        dec = right.decrypt(enc)
        assert dec == b"hello"

    def test_25519(self):
        name = b"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"
        self.do_test_connection(name)

    def test_448(self):
        name = b"Noise_NNpsk0_448_ChaChaPoly_BLAKE2s"
        self.do_test_connection(name)


@pytest.fixture
def protocol_name():
    return b"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"


@pytest.fixture
def connection(protocol_name):
    key = b"\x00" * 32
    left = NoiseConnection.from_name(protocol_name)
    left.set_psks(key)
    left.set_as_initiator()
    left.start_handshake()

    right = NoiseConnection.from_name(protocol_name)
    right.set_psks(key)
    right.set_as_responder()
    right.start_handshake()

    h = left.write_message()
    _ = right.read_message(h)
    h2 = right.write_message()
    left.read_message(h2)

    assert left.handshake_finished
    assert right.handshake_finished

    return left, right


@pytest.mark.parametrize(
    "input_size,success",
    [(x, False) for x in range(65520, 65555, 1)] +  # all too big
    [(x, True) for x in range(0, 65000, 100)] +  # all fine, don't test every size
    [(x, True) for x in range(65256, 65519, 1)]  # also fine
)
def test_limits(connection, success, input_size):
    """
    test around the limits of message sizes to ensure we get proper
    errors
    """
    left, right = connection
    plaintext = b"\xff" * input_size

    if not success:
        try:
            left.encrypt(plaintext)
        except Exception as e:
            return
        assert False, "expected an error on input size {}".format(input_size)

    else:
        enc = left.encrypt(plaintext)
        dec = right.decrypt(enc)
        assert dec == plaintext, "encryption + decryption doesn't match original"
