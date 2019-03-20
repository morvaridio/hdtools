from ecdsa import SigningKey, SECP256k1 as DefaultCurve
from ecdsa.ellipticcurve import Point

from base58 import b58decode, b58encode

from hdtools.conversions import hex_to_bytes, bytes_to_hex, int_to_bytes, bytes_to_int, hex_to_int
from hdtools.message import Message as BaseMessage
from hdtools.network import get_network_attr

from hdtools.nt_utils import modsqrt
from hdtools.crypto_utils import sha256


def f(x, curve=DefaultCurve.curve):
    """
    Compute y**2 = x^3 + ax + b in field FP
    :param x: x
    :param curve: The curve
    :return: result of relation
    """
    return (x ** 3 + curve.a() * x + curve.b()) % curve.p()


def ecdsa_point_creator(x, y):
    return Point(
        curve=DefaultCurve.curve,
        x=x,
        y=y
    )


class PrivateKey(BaseMessage):
    def __init__(self, bts, network='btc'):
        super().__init__(bts)
        self.network = network
        self._key = SigningKey.from_string(
            bts,
            curve=DefaultCurve
        )

    @staticmethod
    def random(network='btc'):
        return PrivateKey(
            SigningKey.generate(curve=DefaultCurve).to_string(),
            network=network
        )

    @staticmethod
    def from_wif(wif: str, network='btc') -> "PrivateKey":
        bts = b58decode(wif)
        network_byte, key, checksum = bts[0:1], bts[1:-4], bts[-4:]

        assert sha256(sha256(network_byte + key))[:4] == checksum, 'Invalid Checksum'
        assert network_byte == get_network_attr('wif', network), 'Invalid Network byte'

        if key.endswith(b'\x01'):
            key = key[:-1]
            compressed = True  # TODO
        else:
            compressed = False  # TODO
        return PrivateKey(key)

    def wif(self, compressed=False):
        extended = get_network_attr('wif', self.network) + self.bytes() + (b'\x01' if compressed else b'')
        hashed = sha256(sha256(extended))
        checksum = hashed[:4]
        return b58encode(extended + checksum)

    def to_public(self):
        point = self._key.get_verifying_key().pubkey.point
        return PublicKey(point, self.network)

    def __repr__(self):
        return f"PrivateKey({self.msg})"

    def sign_hash(self, digest):
        return self._key.sign_digest(digest)


class PublicKey:
    def __init__(self, point, network):
        self.network = network
        self.point = point

    def __eq__(self, other):
        return self.point == other.point

    def __repr__(self):
        return f"PublicKey({self.x()}, {self.y()})"

    def x(self):
        return self.point.x()

    def y(self):
        return self.point.y()

    @staticmethod
    def from_private(private, network='btc'):
        private_key = PrivateKey.from_int(private) if isinstance(private, int) else private
        private_key.network = network
        return private_key.to_public()

    @staticmethod
    def decode(key: bytes, network='btc'):  # TODO Easier implementation
        if key.startswith(b'\x04'):  # uncompressed key
            assert len(key) == 65, 'An uncompressed public key must be 65 bytes long'
            x, y = bytes_to_int(key[1:33]), bytes_to_int(key[33:])
        else:  # compressed key
            assert len(key) == 33, 'A compressed public key must be 33 bytes long'
            x = bytes_to_int(key[1:])
            root = modsqrt(f(x), DefaultCurve.curve.p())
            if key.startswith(b'\x03'):  # odd root
                y = root if root % 2 == 1 else -root % DefaultCurve.curve.p()
            elif key.startswith(b'\x02'):  # even root
                y = root if root % 2 == 0 else -root % DefaultCurve.curve.p()
            else:
                assert False, 'Wrong key format'

        return PublicKey(ecdsa_point_creator(x, y), network=network)

    @staticmethod
    def from_hex(hex_string: str, network='btc'):
        return PublicKey.decode(hex_to_bytes(hex_string), network)

    def encode(self, compressed=False) -> bytes:  # TODO Maybe easier Implementation
        if compressed:
            if self.y() & 1:  # odd root
                return b'\x03' + int_to_bytes(self.x()).rjust(32, b'\x00')
            else:  # even root
                return b'\x02' + int_to_bytes(self.x()).rjust(32, b'\x00')
        return b'\x04' + int_to_bytes(self.x()).rjust(32, b'\x00') + int_to_bytes(self.y()).rjust(32, b'\x00')

    def hex(self, compressed=False) -> str:
        return bytes_to_hex(self.encode(compressed=compressed))

    def to_address(self, address_type, compressed=None):
        from hdtools.address import Address
        if compressed is not False and address_type == 'P2PKH':
            return Address.from_public_key(self, address_type, compressed=True)
        return Address.from_public_key(self, address_type)
