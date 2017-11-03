noiseprotocol
=============
[![Build Status](https://travis-ci.org/plizonczyk/noiseprotocol.svg?branch=master)](https://travis-ci.org/plizonczyk/noiseprotocol)
[![PyPI](https://img.shields.io/pypi/v/noiseprotocol.svg)](https://pypi.python.org/pypi/noiseprotocol)
[![Documentation Status](https://readthedocs.org/projects/noiseprotocol/badge/)](http://noiseprotocol.readthedocs.io/)

This repository contains source code of **noiseprotocol** - a Python 3 implementation of [Noise Protocol Framework](http://www.noiseprotocol.org/).
Compatible with revisions 32 and 33.

### Warning
This package shall not be used (yet) for production purposes. There was little to none peer review done so far. 
Use common sense while using - until this package becomes stable.

## Documentation
Available on [Read the Docs](https://noiseprotocol.readthedocs.io). For now it provides basic documentation on 
HandshakeState, CipherState and SymmetricState. Refer to the rest of the README below for more information.

## Installation and prerequisites
For now, only Python 3.5+ is supported.
The author provides support for Linux systems only. Although the CI systems perform testing on **Windows and OS X**, consider their support even **more experimental** than the whole package, though OS X usage should not differ from Linux.

*Unless there is a dedicated contributor for Windows, the author won't provide any support for issues with using the noiseprotocol package on them. Python development on Windows is too painful, even considering my deep love for the OS.*

Install via pip:
```
pip install noiseprotocol 
```
*noiseprotocol* depends on [Cryptography](https://github.com/pyca/cryptography/) package (and its' pre-packaged OpenSSL v1.1) as a source of crypto-primitives. 
 
## Usage

#### Basic usage
NoiseConnection class provides highest level of abstraction for the package. You can access full functionality of the package
through this class' interfaces. An example for setting up NoiseConnection could look like this:

```python
import socket

from noise.connection import NoiseConnection

sock = socket.socket()
sock.connect(('localhost', 2000))

# Create instance of NoiseConnection, set up to use NN handshake pattern, Curve25519 for
# elliptic curve keypair, ChaCha20Poly1305 as cipher function and SHA256 for hashing.  
proto = NoiseConnection.from_name(b'Noise_NN_25519_ChaChaPoly_SHA256')

# Set role in this connection as initiator
proto.set_as_initiator()
# Enter handshake mode
proto.start_handshake()

# Perform handshake - as we are the initiator, we need to generate first message. 
# We don't provide any payload (although we could, but it would be cleartext for this pattern).
message = proto.write_message()
# Send the message to the responder - you may simply use sockets or any other way 
# to exchange bytes between communicating parties. 
sock.sendall(message)
# Receive the message from the responder 
received = sock.recv(2048)
# Feed the received message into noise
payload = proto.read_message(received)

# As of now, the handshake should be finished (as we are using NN pattern). 
# Any further calls to write_message or read_message would raise NoiseHandshakeError exception.
# We can use encrypt/decrypt methods of NoiseConnection now for encryption and decryption of messages.
encrypted_message = proto.encrypt(b'This is an example payload')
sock.sendall(encrypted_message)

ciphertext = sock.recv(2048)
plaintext = proto.decrypt(ciphertext)
print(plaintext)
```

The example above covers the connection from the initiator's ("client") point of view. The snippet below is an example of responder's code ("server") using a socket connection to send and receive ciphertext.

```python
import socket
from itertools import cycle

from noise.connection import NoiseConnection

if __name__ == '__main__':
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('localhost', 2000))
    s.listen(1)

    conn, addr = s.accept()
    print('Accepted connection from', addr)

    noise = NoiseConnection.from_name(b'Noise_NN_25519_ChaChaPoly_SHA256')
    noise.set_as_responder()
    noise.start_handshake()

    # Perform handshake. Break when finished
    for action in cycle(['receive', 'send']):
        if noise.handshake_finished:
            break
        elif action == 'send':
            ciphertext = noise.write_message()
            conn.sendall(ciphertext)
        elif action == 'receive':
            data = conn.recv(2048)
            plaintext = noise.read_message(data)

    # Endless loop "echoing" received data
    while True:
        data = conn.recv(2048)
        if not data:
            break
        received = noise.decrypt(data)
        conn.sendall(noise.encrypt(received))
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

- [ ] custom crypto backends
- [ ] fallback patterns support
- [ ] scripts for keypair generation (+ console entry points)
- [ ] "echo" (noise-c like) example
- [ ] extensive logging
- [ ] move away from custom ed448 implementation
- [ ] implement countermeasures for side-channel attacks
- [ ] **get peer review of the code**

You are more than welcome to propose new things to this list and/or implement them and file a merge request.

Contact the author: plizonczyk.public [at] gmail.com

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
