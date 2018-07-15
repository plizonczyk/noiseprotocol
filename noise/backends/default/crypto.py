DHLEN = 56
P = 2 ** 448 - 2 ** 224 - 1
A24 = 39081


class X448(object):
    # Based on RFC 7748 and heavily relying on it - https://tools.ietf.org/html/rfc7748#section-5
    # Modified mostly to fulfill python3 changes
    # Almost surely unsafe from side-channel attacks.
    # Should be replaced with safer implementation (most likely one from OpenSSL and/or pyca/Cryptography)
    @staticmethod
    def decode_little_endian(b):
        assert len(b) == DHLEN
        return sum([b[i] << 8 * i for i in range(DHLEN)])

    @staticmethod
    def decode_u_coordinate(u):
        u[-1] &= (1 << 56) - 1
        return X448.decode_little_endian(u)

    @staticmethod
    def encode_u_coordinate(u):
        return bytes([(u >> 8 * i) & 255 for i in range(DHLEN)])

    @staticmethod
    def decode_scalar448(k):
        k = [b for b in k]
        k[0] &= 252
        k[55] |= 128
        return X448.decode_little_endian(k)

    @staticmethod
    def cswap(swap, x2, x3):
        dummy = (swap * (x2 - x3)) % P
        x2 = (x2 - dummy) % P
        x3 = (x3 + dummy) % P
        return x2, x3

    @staticmethod
    def x448(k, u):
        x1 = u
        x2 = 1
        z2 = 0
        x3 = u
        z3 = 1
        swap = 0

        for t in range(448-1, -1, -1):
            k_t = (k >> t) & 1
            swap ^= k_t
            x2, x3 = X448.cswap(swap, x2, x3)
            z2, z3 = X448.cswap(swap, z2, z3)
            swap = k_t

            a = (x2 + z2) % P
            aa = (a * a) % P
            b = (x2 - z2) % P
            bb = (b * b) % P
            e = (aa - bb) % P
            c = (x3 + z3) % P
            d = (x3 - z3) % P
            da = (d * a) % P
            cb = (c * b) % P
            x3 = pow((da + cb) % P, 2, P)
            z3 = (x1 * pow((da - cb) % P, 2, P)) % P
            x2 = (aa * bb) % P
            z2 = (e * ((aa + (A24 * e) % P) % P)) % P

        x2, x3 = X448.cswap(swap, x2, x3)
        z2, z3 = X448.cswap(swap, z2, z3)

        return (x2 * pow(z2, P - 2, P)) % P

    @staticmethod
    def mul(n, p):
        return X448.encode_u_coordinate(X448.x448(X448.decode_scalar448(n), X448.decode_little_endian(p)))

    @staticmethod
    def mul_5(n):
        return X448.encode_u_coordinate(X448.x448(X448.decode_scalar448(n), 5))


# Self-test
# Test vectors taken from RFC 7748 section 5.2 and 6.2
scalar1 = bytes.fromhex(
    '203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f')
u1 = bytes.fromhex(
    '0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db')
assert X448.mul(scalar1, u1) == bytes.fromhex(
    '884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d')

scalar2 = bytes.fromhex(
    '3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3')
u2 = bytes.fromhex(
    '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086')
assert X448.mul(scalar2, u2) == bytes.fromhex(
    'ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f')

alice_priv = bytes.fromhex(
    '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b')
alice_pub = bytes.fromhex(
    '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0')
bob_priv = bytes.fromhex(
    '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d')
bob_pub = bytes.fromhex(
    '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609')
assert alice_pub == X448.mul_5(alice_priv)
assert bob_pub == X448.mul_5(bob_priv)
assert X448.mul(alice_priv, bob_pub) == X448.mul(bob_priv, alice_pub) == bytes.fromhex(
    '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d')
