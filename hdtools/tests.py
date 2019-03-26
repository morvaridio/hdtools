from unittest import TestCase, main as test_main

from hdtools.extended_keys import XPrv, XPub
from hdtools.keys import PrivateKey, PublicKey
from hdtools.opcodes import AddressType


class TestKeys(TestCase):
    def test_wif(self):
        """
        Test import WIF format
        https://en.bitcoin.it/wiki/Wallet_import_format
        """

        # WIF to PrivateKey
        private_key = PrivateKey.from_wif('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
        self.assertEqual(
            private_key.hex(),
            '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d'
        )

        # PrivateKey to WIF
        private_key = PrivateKey.from_hex('2BD036D77C4FE1F4DAFEAA005A1DC7F69522E4B3B53E7F537FA16C5ED5986D03')
        self.assertEqual(
            private_key.wif(compressed=False).decode(),
            '5J9ajYkr763m6HvUkGar3nybCL4e5UMYRP1svduPM3fx1paSK6o'
        )

    def test_private_to_public(self):
        private = PrivateKey.from_wif('L2AnMo4KYaNTKFwgd2ZSsgcxAo8QSwJ9QYSiBSm44a4WZrwPKTum')
        self.assertEqual(
            private.to_public(),
            PublicKey.from_hex('03b82761f2482254b93fdf45f26c5d00bd51883fb7cd143080318c5be9746a5f5f')
        )

    def test_address_creation(self):
        """
        Test address creation
        https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        """
        self.assertEqual(
            PublicKey.from_hex('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352').to_address(
                'P2PKH',
            ),
            '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs'
        )

        self.assertNotEqual(
            PublicKey.from_hex('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352').to_address(
                'P2PKH',
                compressed=False
            ),
            '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs'
        )

        self.assertEqual(
            PublicKey.from_hex('03b82761f2482254b93fdf45f26c5d00bd51883fb7cd143080318c5be9746a5f5f').to_address(
                'P2WPKH-P2SH'),
            '33x3UHfxVvJNqd275WG9XprVfepEUeASoj'
        )

        self.assertEqual(
            PublicKey.from_hex('03727fcbaff7eadb840b13bfd5b3d258530f0c1208bf02d8537606d096f069d2b5').to_address(
                'P2WPKH'),
            'bc1qsxe29au72mvjf7vsfhmlcdd5seuslnnkmgw4ws'
        )


class TestExtendedKeys(TestCase):
    """
    All test-cases can be checked on https://iancoleman.io/bip39/
    """

    def test_seed(self):
        self.assertEqual(
            XPrv.from_seed(
                seed='66d35ff22d901d8ba764a07d8667eb282678fb9954712841494faf22b5d1a2'
                     '0b0a36ae8c3556a23caeb7bf33ed5b8d2ebd49de31a8c738c66067621730a16880'
            ).encode(),
            b'xprv9s21ZrQH143K38p5ouMV2qFYest2F3uRQC51JPLqsdi8Lh1rkXUJRUy1m7rd5TvooJn6gert'
            b'hNmntuJag6e73mrf8GmG96Ua8rpayQtUEsL'
        )

    def test_mnemonic(self):
        self.assertEqual(
            XPrv.from_mnemonic(
                mnemonic='lemon child success once board usual cigar buffalo video cheese kitten onion build axis dose'
            ).encode(),
            b'xprv9s21ZrQH143K38p5ouMV2qFYest2F3uRQC51JPLqsdi8Lh1rkXUJRUy1m7rd5TvooJn6gert'
            b'hNmntuJag6e73mrf8GmG96Ua8rpayQtUEsL'
        )

        self.assertEqual(
            XPrv.from_mnemonic(
                mnemonic='lemon child success once board usual cigar buffalo video cheese kitten onion build axis dose',
                network='btct'
            ).encode(),
            b'tprv8ZgxMBicQKsPdx3cUUCzCUsXy1JEUZwRjjz8AomJMcCc8Hkwjtp3wELTgJ2H5qK8AkJsgkUer'
            b'jMbMkrKoJz3rq8FeuyZoTCd3xa1R23x4LZ'
        )

    def test_key_generation(self):
        # First Key
        M = XPrv.from_mnemonic('lemon child success once board usual cigar '
                               'buffalo video cheese kitten onion build axis dose')

        self.assertEqual(
            (M / 44. / 0. / 0. / 0 / 0).address(),
            '1DgEh5Y6NioqaxHBBc2puDYq6SvG5NDsG9'
        )

        self.assertEqual(
            (M / 49. / 0. / 0. / 0 / 0).address(AddressType.P2WPKH_P2SH.value),
            '39Qn8kHG6h7zv1Fh1iwjjyeRibx7gHTq1Z'
        )

        self.assertEqual(
            (M / 84. / 0. / 0. / 0 / 0).address(AddressType.P2WPKH.value),
            'bc1qrxxtlul9j3p95wrt33zg7vdf74skujnhnghaey'
        )


if __name__ == '__main__':
    test_main()
