noiseprotocol
=============
[![Build Status](https://travis-ci.org/plizonczyk/noiseprotocol.svg?branch=master)](https://travis-ci.org/plizonczyk/noiseprotocol)

This repository contains source code of **noiseprotocol** - a Python 3 implementation of [Noise Protocol Framework](http://www.noiseprotocol.org/).

### Warning
This package shall not be used (yet) for production purposes. There was little to none peer review done so far. 
Use common sense while using - until this package becomes stable.

## Installation and prerequisites
For now, only Python 3.6 is supported.

Install via pip:
```
pip install noiseprotocol 
```
*noiseprotocol* depends on [Cryptography](https://github.com/pyca/cryptography/) package (and its' pre-packaged OpenSSL v1.1) as a source of crypto-primitives. 
 
## Usage

#### Basic usage
NoiseBuilder class provides highest level of abstraction for the package. You can access full functionality of the package
through this class' interfaces. An example for setting up NoiseBuilder could look like this:

```python
from noise.builder import NoiseBuilder

# Create instance of NoiseBuilder, set up to use NN handshake pattern, Curve25519 for 
# elliptic curve keypair, ChaCha20Poly1305 as cipher function and SHA256 for hashing.  
proto = NoiseBuilder.from_name('Noise_NN_25519_ChaChaPoly_SHA256')

# Set role in this connection as initiator
proto.set_as_initiator()
# Enter handshake mode
proto.start_handshake()

# Perform handshake - as we are the initiator, we need to generate first message. 
# We don't provide any payload (although we could, but it would be cleartext for this pattern).
message = proto.write_message()
# Send the message to the responder - you may simply use sockets or any other way 
# to exchange bytes between communicating parties. 
# For clarity - we omit socket creation in this example.
sock.send(message)
# Receive the message from the responder 
received = sock.recv()
# Feed the received message into noise
payload = proto.read_message(received)

# As of now, the handshake should be finished (as we are using NN pattern). 
# Any further calls to write_message or read_message would raise NoiseHandshakeError exception.
# We can use encrypt/decrypt methods of NoiseBuilder now for encryption and decryption of messages.
encrypted_message = proto.encrypt('This is an example payload')

ciphertext = sock.recv()
plaintext = proto.decrypt(ciphertext)
```

#### Wireguard integration example
In *examples* directory, there is an example of interoperation of this package with Wireguard VPN solution. Please refer to [README.md](examples/wireguard/README.md) of that example for details.

----
## Bug reports
This software was tested only on Linux. It may or may not work on Windows, explicit support for this system will be added in future.

Please file any bug reports in project's [issue tracker](https://github.com/plizonczyk/noiseprotocol/issues). 

## Development & contributing
The only additional package that may be useful during development is pytest - for unit testing.
Installation:

```
pip install pytest
```

Running tests (from root directory):
```
pytest
```

### Todo-list for the project:

- [ ] fallback patterns support
- [ ] documentation on Read the Docs and more extensive readme
- [ ] scripts for keypair generation (+ console entry points)
- [ ] "echo" (noise-c like) example
- [ ] extensive logging
- [ ] bringing back Python 3.5 support and supporting Python 3.7 (dependent on Cryptography package updates)
- [ ] move away from custom ed448 implementation
- [ ] implement countermeasures for side-channel attacks
- [ ] **get peer review of the code**

You are more than welcome to propose new things to this list and/or implement them and file a merge request.

Contact the author: plizonczyk.public [at] gmail.com

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
