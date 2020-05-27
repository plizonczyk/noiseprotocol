"""Test get public feature for NoiseConnection class."""

import base64
import typing

from noise.connection import NoiseConnection
from noise.connection import Keypair


_Keys = typing.NamedTuple(
    'Keys',
    [
        ('initiator_private', bytes),
        ('initiator_public', bytes),
        ('responder_private', bytes),
        ('responder_public', bytes),
    ]
)

def _do_test_for(key_type: str, keys: _Keys):
    noise_name = 'Noise_XX_{}_ChaChaPoly_SHA256'.format(key_type).encode()
    initiator = NoiseConnection.from_name(noise_name)
    responder = NoiseConnection.from_name(noise_name)
    initiator.set_as_initiator()
    responder.set_as_responder()

    initiator.set_keypair_from_private_bytes(Keypair.STATIC, keys.initiator_private)
    responder.set_keypair_from_private_bytes(Keypair.STATIC, keys.responder_private)

    initiator.start_handshake()
    responder.start_handshake()

    message = b'public-key-test'
    assert message == responder.read_message(initiator.write_message(message))
    assert message == initiator.read_message(responder.write_message(message))
    assert message == responder.read_message(initiator.write_message(message))

    # Test ability to get remote static public key,
    # which is essential for application layer to validate peer identity
    assert keys.responder_public == initiator.get_public_bytes(Keypair.REMOTE_STATIC)
    assert keys.initiator_public == responder.get_public_bytes(Keypair.REMOTE_STATIC)

    # Other tests
    assert initiator.get_public_bytes(Keypair.REMOTE_EPHEMERAL) == responder.get_public_bytes(Keypair.EPHEMERAL)
    assert responder.get_public_bytes(Keypair.REMOTE_EPHEMERAL) == initiator.get_public_bytes(Keypair.EPHEMERAL)


def test_x25519_get_public_key():
    """Test get public key for x25519."""
    _do_test_for(
        '25519',
        _Keys(
            base64.b64decode(b'+BWGKo59m/EjzLAIDb2WlIMKRwilG8G70rKiBvaDgm0='),
            base64.b64decode(b'7zOPAAeyz9CRHHdi0d5ntdk2TwYKiHYmx7tX34rJXgA='),
            base64.b64decode(b'ODyYIHfQ2W47bVek/B8NS06n2bXex12omxqb5C7bu24='),
            base64.b64decode(b'xqkyauPBj6Ogcn6WT5p35pt0NKSByuF4RBk/JR+rHys='),
        ),
    )


def test_x448_get_public_key():
    """Test get public key for 448."""
    _do_test_for(
        '448',
        _Keys(
            base64.b64decode(b'nJUX8VL2G7yZsuNHnb/kEA1HT+sdexEQyDg7M6dQj3lkzrE8IPpAkwy0N9ScWGYc1NY9ODQXzNQ='),
            base64.b64decode(b'6jmDfnjy428DZWP8G3wOrFOim0CJFAylGjxquGWXcN0pBL1srYMz9ftHkSK4zXxpxeCa5qZBc5Y='),
            base64.b64decode(b'FH2DokPJMRUYyOwgo9IwAMd5txaUU4yr8gxzjEzSZrpeZ1vsdtEELDR6ylN99wRvfyjceK7jZfk='),
            base64.b64decode(b'G4w7WRu5KnEC1W8iH90/priXAe/r5OaU5l2/5zWgJAyDMtXGf6zfAs23khPI5uxV/hP1zM3ItwY='),
        ),
    )
