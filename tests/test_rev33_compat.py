from noise.noise_protocol import NoiseProtocol
from noise.state import CipherState, SymmetricState


class TestRevision33Compatibility(object):
    def test_noise_protocol_accepts_slash(self):
        class FakeSHA3_256():
            fn = None

        noise_name = b"Noise_NN_25519_AESGCM_SHA3/256"
        modified_class = NoiseProtocol
        modified_class.methods['hash']['SHA3/256'] = FakeSHA3_256  # Add callable to hash functions mapping
        modified_class(noise_name)

    def test_cipher_state_set_nonce(self):
        noise_protocol = NoiseProtocol(b"Noise_NN_25519_AESGCM_SHA256")
        cipher_state = CipherState(noise_protocol)
        cipher_state.initialize_key(b'\x00'*32)
        assert cipher_state.n == 0
        cipher_state.set_nonce(42)
        assert cipher_state.n == 42

    def test_symmetric_state_get_handshake_hash(self):
        symmetric_state = SymmetricState()
        symmetric_state.h = 42
        assert symmetric_state.get_handshake_hash() == 42
