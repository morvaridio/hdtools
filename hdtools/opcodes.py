from enum import Enum


class AddressType(Enum):
    P2PK = 'P2PK'
    P2PKH = 'P2PKH'
    P2SH = 'P2SH'
    P2WPKH = 'P2WPKH'
    P2WSH = 'P2WSH'
    P2WPKH_P2SH = 'P2WPKH-P2SH'
    P2WSH_P2SH = 'P2WSH-P2SH'
