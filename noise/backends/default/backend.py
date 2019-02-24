from noise.backends.default.ciphers import ChaCha20Cipher, AESGCMCipher
from noise.backends.default.diffie_hellmans import ED25519, ED448
from noise.backends.default.hashes import hmac_hash, BLAKE2sHash, BLAKE2bHash, SHA256Hash, SHA512Hash
from noise.backends.default.keypairs import KeyPair25519, KeyPair448
from noise.backends.noise_backend import NoiseBackend


class DefaultNoiseBackend(NoiseBackend):
    """
    Contains all the crypto methods endorsed by Noise Protocol specification, using Cryptography as backend
    """

    def __init__(self):
        super(DefaultNoiseBackend, self).__init__()

        self.diffie_hellmans = {
            '25519': ED25519,
            '448': ED448
        }

        self.ciphers = {
            'AESGCM': AESGCMCipher,
            'ChaChaPoly': ChaCha20Cipher
        }

        self.hashes = {
            'BLAKE2s': BLAKE2sHash,
            'BLAKE2b': BLAKE2bHash,
            'SHA256': SHA256Hash,
            'SHA512': SHA512Hash
        }

        self.keypairs = {
            '25519': KeyPair25519,
            '448': KeyPair448
        }

        self.hmac = hmac_hash
