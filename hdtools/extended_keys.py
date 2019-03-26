"""
Implementation of BIP32, BIP49, BIP84, ...
References:
    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-functions
    https://iancoleman.io/bip39/
"""
import hashlib
from typing import Union

from base58 import b58encode, b58decode
import hmac

from mnemonic import Mnemonic

from hdtools.conversions import bytes_to_int, int_to_bytes, bytes_to_hex, hex_to_bytes
from hdtools.network import get_network_attr
from hdtools.opcodes import AddressType
from hdtools.keys import PrivateKey, PublicKey, DefaultCurve
from hdtools.crypto_utils import hash160, sha256, sha512

Key = Union[PrivateKey, PublicKey]


class ExtendedKey:
    root_path = NotImplemented

    def __init__(self, key: Key, code: bytes, depth=0, i=None, parent=b'\x00\x00\x00\x00', path=None,
                 address_type='P2PKH'):
        self.key = key
        self.code = code

        assert depth in range(256), 'Depth can only be 0-255'
        self.depth = depth
        if i is not None:
            assert 0 <= i < 1 << 32, f'Invalid i: {i}'
        self.i = i
        self.parent = parent
        self.path = path or self.root_path

        assert (
                       self.depth == 0 and
                       self.i is None and
                       self.parent == b'\x00\x00\x00\x00' and
                       self.path == self.root_path
               ) or (
                       self.depth != 0 and
                       self.i is not None and
                       self.parent != b'\x00\x00\x00\x00' and
                       self.path != self.root_path
               ), f"Unable to determine if root path (" \
            f"depth={self.depth}, i={self.i}, " \
            f"path={self.path}, " \
            f"parent={bytes_to_hex(self.parent)})"

        self.type = AddressType(address_type)

    def child(self, i):
        raise NotImplementedError

    def is_master(self):
        return self.depth == 0 and \
               self.i is None and \
               self.parent == b'\x00\x00\x00\x00' and \
               self.path == self.root_path

    def __truediv__(self, other):
        if isinstance(other, float):
            # hardened child derivation
            i = int(other) + 2 ** 31
        elif isinstance(other, int):
            # non-hardened child derivation
            i = other
        else:
            raise TypeError
        return self.child(i)

    def __floordiv__(self, other):
        if not isinstance(other, int):
            raise TypeError
        return self.child(other + 2 ** 31)

    def id(self):
        raise NotImplementedError

    def fingerprint(self):
        return self.id()[:4]

    def serialize(self):
        raise NotImplementedError

    def encode(self):
        data = self.serialize()
        assert len(data) == 78
        checksum = sha256(sha256(data))[:4]
        return b58encode(data + checksum)

    @classmethod
    def deserialize(cls, bts: bytes, network='btc'):
        def read(n):
            nonlocal bts
            data, bts = bts[:n], bts[n:]
            return data

        net = read(4)
        is_private = net in get_network_attr('extended_prv', network).values()
        is_public = net in get_network_attr('extended_pub', network).values()
        assert is_public ^ is_private, f'Invalid network bytes : {bytes_to_hex(net)}'
        address_lookup = {val: key for key, val in (
            get_network_attr('extended_prv', network) if is_private else get_network_attr('extended_pub',
                                                                                          network)).items()}
        constructor = XPrv if is_private else XPub
        depth = bytes_to_int(read(1))
        assert depth in range(256), f'Invalid depth : {depth}'
        fingerprint = read(4)
        i = bytes_to_int(read(4))
        if depth == 0:
            i = None
            path = None
        else:
            ih = f'{i}' if i < 2 ** 31 else f"{i - 2 ** 31}h"
            path = '/'.join([constructor.root_path] + ['x' for _ in range(depth - 1)] + [ih])

        code = read(32)
        key = read(33)
        key = PrivateKey(key, network=network) if is_private else PublicKey.decode(key, network=network)
        assert not bts, 'Leftover bytes'
        return constructor(key, code, depth=depth, i=i, parent=fingerprint, path=path, address_type=address_lookup[net])

    @classmethod
    def decode(cls, string: str, network='btc'):
        bts = b58decode(string)
        assert len(bts) == 82, f'Invalid length {len(bts)}'
        data, checksum = bts[:78], bts[78:]
        assert sha256(sha256(data)).startswith(checksum), 'Invalid checksum'
        return cls.deserialize(data, network)

    def __eq__(self, other):
        return self.encode() == other.encode


class KeyDerivationError(Exception):  # TODO
    pass


class XPrv(ExtendedKey):
    root_path = 'm'

    def child(self, i) -> 'XPrv':
        hardened = i >= 1 << 31

        if hardened:
            I = hmac.new(
                key=self.code,
                msg=self.key_data() + int_to_bytes(i).rjust(4, b'\x00'),
                digestmod=hashlib.sha512
            ).digest()
        else:
            I = hmac.new(
                key=self.code,
                msg=self.key.to_public().encode(compressed=True) + int_to_bytes(i).rjust(4, b'\x00'),
                digestmod=hashlib.sha512
            ).digest()

        I_L, I_R = bytes_to_int(I[:32]), I[32:]
        key = (I_L + self.key.int()) % DefaultCurve.order

        if I_L >= DefaultCurve.order or key == 0:
            return self.child(i + 1)

        ret_code = I_R
        if hardened:
            path = self.path + f'/{i - 2 ** 31}h'
        else:
            path = self.path + f'/{i}'

        private = PrivateKey.from_int(key)
        private.network = self.key.network
        return XPrv(
            key=private,
            code=ret_code,
            depth=self.depth + 1,
            i=i,
            parent=self.fingerprint(),
            path=path,
            address_type=self.type.value
        )

    def to_xpub(self) -> 'XPub':
        return XPub(
            self.key.to_public(),
            self.code,
            depth=self.depth,
            i=self.i,
            parent=self.parent,
            path=self.path.replace('m', 'M'),
            address_type=self.type.value
        )

    def to_child_xpub(self, i: int) -> 'XPub':
        # return self.child(i).to_xpub()  # works always
        return self.to_xpub().child(i)  # works only for non-hardened child keys

    def id(self):
        return hash160(self.key.to_public().encode(compressed=True))

    def key_data(self):
        return self.key.bytes().rjust(33, b'\x00')

    def serialize(self):
        version = get_network_attr('extended_prv', self.key.network)[self.type]
        depth = int_to_bytes(self.depth)
        child = bytes(4) if self.is_master() else int_to_bytes(self.i).rjust(4, b'\x00')
        return version + depth + self.parent + child + self.code + self.key_data()

    @staticmethod
    def from_seed(seed: Union[bytes, str], address_type='P2PKH', network='btc') -> 'XPrv':
        if isinstance(seed, str):
            seed = hex_to_bytes(seed)
        assert 16 <= len(seed) <= 64, 'Seed should be between 128 and 512 bits'

        I = hmac.new(key=b"Bitcoin seed", msg=seed, digestmod=hashlib.sha512).digest()
        I_L, I_R = I[:32], I[32:]
        if bytes_to_int(I_L) == 0 or bytes_to_int(I_L) > DefaultCurve.order:
            raise KeyDerivationError

        key, code = PrivateKey(I_L, network=network), I_R
        return XPrv(key, code, address_type=address_type)

    @staticmethod
    def from_mnemonic(mnemonic: str, pass_phrase='', address_type='P2PKH', network='btc'):
        seed = Mnemonic.to_seed(mnemonic, pass_phrase)
        return XPrv.from_seed(seed, address_type, network)

    def address(self, address_type=None):
        return self.key.to_public().to_address(address_type or self.type.value, compressed=True)


class XPub(ExtendedKey):
    root_path = 'M'

    def child(self, i: int) -> 'XPub':
        hardened = i >= 1 << 31

        if hardened:
            raise KeyDerivationError('Cannot derive a hardened key from an extended public key')

        I = hmac.new(key=self.code, msg=self.key_data() + int_to_bytes(i).rjust(4, b'\x00'),
                     digestmod=hashlib.sha512).digest()

        I_L, I_R = I[:32], I[32:]

        key = PrivateKey(I_L).to_public().point + self.key.point
        ret_code = I_R
        path = self.path + f'/{i}'

        # TODO add point at infinity check
        return XPub(
            PublicKey(key, network=self.key.network),
            ret_code,
            depth=self.depth + 1,
            i=i,
            parent=self.fingerprint(),
            path=path,
            address_type=self.type.value
        )

    def id(self):
        return hash160(self.key.encode(compressed=True))

    def key_data(self):
        return self.key.encode(compressed=True)

    def serialize(self):
        version = get_network_attr('extended_pub', self.key.network)[self.type]
        depth = int_to_bytes(self.depth)
        child = bytes(4) if self.is_master() else int_to_bytes(self.i).rjust(4, b'\x00')
        return version + depth + self.parent + child + self.code + self.key_data()

    def __repr__(self):
        return f"{self.__class__.__name__}(path={self.path}, key={self.key.hex(compressed=True)}"

    def address(self, address_type=None):
        return self.key.to_address(address_type or self.type.value, compressed=True)
