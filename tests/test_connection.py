from noise.connection import NoiseConnection

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
