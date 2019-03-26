from base58 import b58encode

from hdtools import bech32
from hdtools.keys import PublicKey
from hdtools.crypto_utils import hash160
from hdtools.network import get_network_attr
from hdtools.script import witness_byte, push
from hdtools.crypto_utils import sha256
from hdtools.opcodes import AddressType


def legacy_address(public_key: PublicKey, version_byte: bytes) -> str:
    """https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses"""
    bts = public_key.encode(compressed=False) if isinstance(public_key, PublicKey) else public_key
    hashed = hash160(bts)
    payload = version_byte + hashed
    return hashed_payload_to_address(payload)


def hashed_payload_to_address(payload) -> str:
    checksum = sha256(sha256(payload))[:4]
    address = payload + checksum
    return b58encode(address).decode()


def pubkey_to_bech32(public_key: PublicKey, witver: int) -> str:
    """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
    witprog = hash160(public_key.encode(compressed=True))
    return bech32.encode(
        get_network_attr('hrp', public_key.network),
        witver,
        witprog)


class Address:
    @staticmethod
    def to_p2pkh(public_key: PublicKey, compressed=False) -> 'str':
        return legacy_address(
            public_key.encode(compressed=True) if compressed else public_key,
            version_byte=get_network_attr('keyhash', public_key.network)
        )

    @staticmethod
    def to_p2wpkh_p2sh(public_key: PublicKey) -> 'str':
        return legacy_address(
            witness_byte(witver=0) + push(hash160(public_key.encode(compressed=True))),
            version_byte=get_network_attr('scripthash', public_key.network)
        )

    @staticmethod
    def to_p2wpkh(public_key: PublicKey) -> 'str':
        return pubkey_to_bech32(public_key, witver=0x00)

    @staticmethod
    def from_public_key(public_key: PublicKey, version='P2PKH', compressed=False) -> 'str':
        key_to_addr_versions = {
            AddressType.P2PKH: Address.to_p2pkh,
            AddressType.P2WPKH_P2SH: Address.to_p2wpkh_p2sh,
            AddressType.P2WPKH: Address.to_p2wpkh
        }

        if version == AddressType.P2PKH.value:
            return key_to_addr_versions[AddressType(version)](public_key, compressed)

        return key_to_addr_versions[AddressType(version)](public_key)
