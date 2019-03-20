from enum import Enum, unique

from hdtools.opcodes import AddressType


@unique
class NETWORK(Enum):
    BTC_MAIN = 'btc'
    BTC_TEST = 'btct'


btc_main = {
    'hrp': 'bc',
    'keyhash': b'\x00',
    'scripthash': b'\x05',
    'wif': b'\x80',
    'extended_prv': {
        # https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst
        AddressType.P2PKH: b'\x04\x88\xad\xe4',  # xprv
        AddressType.P2WPKH: b'\x04\xb2\x43\x0c',  # zprv
        AddressType.P2WSH: b'\x02\xaa\x7a\x99',  # Zprv
        AddressType.P2WPKH_P2SH: b'\x04\x9d\x78\x78',  # yprv
        AddressType.P2WSH_P2SH: b'\x02\x95\xb4\x3f'  # Yprv
    },
    'extended_pub': {
        # https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst
        AddressType.P2PKH: b'\x04\x88\xb2\x1e',  # xpub
        AddressType.P2WPKH: b'\x04\xb2\x47\x46',  # zpub
        AddressType.P2WSH: b'\x02\xaa\x7e\xd3',  # Zpub
        AddressType.P2WPKH_P2SH: b'\x04\x9d\x7c\xb2',  # ypub
        AddressType.P2WSH_P2SH: b'\x02\x95\xb4\x3f'  # Ypub
    },
    'utxo_url': 'https://blockchain.info/unspent?active={address}',
    'rawtx_url': 'https://blockchain.info/rawtx/{txid}?format=hex',
    'broadcast_url': 'https://blockchain.info/pushtx'

}

btc_test = {
    'hrp': 'tb',
    'keyhash': b'\x6f',
    'scripthash': b'\xc4',
    'wif': b'\xef',
    'extended_prv': {
        # https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst
        AddressType.P2PKH: b'\x04\x35\x83\x94',  # tprv
        AddressType.P2WPKH: b'\x04\x5f\x18\xbc',  # vprv
        AddressType.P2WSH: b'\x02\x57\x50\x48',  # Vprv
        AddressType.P2WPKH_P2SH: b'\x04\x4a\x4e\x28',  # uprv
        AddressType.P2WSH_P2SH: b'\x02\x42\x85\xb5'  # Uprv
    },
    'extended_pub': {
        # https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst
        AddressType.P2PKH: b'\x04\x35\x87\xcf',  # tpub
        AddressType.P2WPKH: b'\x04\x5f\x1c\xf6',  # vpub
        AddressType.P2WSH: b'\x02\x57\x54\x83',  # Vpub
        AddressType.P2WPKH_P2SH: b'\x04\x4a\x52\x62',  # upub
        AddressType.P2WSH_P2SH: b'\x02\x42\x89\xef'  # Upub
    },
    'utxo_url': 'https://testnet.blockchain.info/unspent?active={address}',
    'rawtx_url': 'https://testnet.blockchain.info/rawtx/{txid}?format=hex',
    'broadcast_url': 'https://testnet.blockchain.info/pushtx'
}

networks = {
    NETWORK.BTC_MAIN: btc_main,
    NETWORK.BTC_TEST: btc_test
}


def get_network_attr(attr, network='btc'):
    return networks[NETWORK(network)][attr]
