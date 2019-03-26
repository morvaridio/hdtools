# hdtools [![Build Status](https://travis-ci.org/morvaridio/hdtools.svg?branch=master)](https://travis-ci.org/morvaridio/hdtools)
HD Tools for cyrptocurrencies like BTC, and BTCt
base on [mcdallas/cryptotools](https://github.com/mcdallas/cryptotools).

## Requirements
1. Create an virtualenv:
    ```sh
    virtualenv -p python3 .env
    ```
1. Install requirements:
    ```sh
    pip install -r requirements
    ```
1. Use library:
    ```python
    from hdtools.extended_keys import *
    private_key = XPrv.from_mnemonic('mnemonic phrase')
    private_key.encode() 
    ```
    
## How to install
```bash
pip install hdtools
```
    
## Examples
Create HD Wallets
```python
>>> from hdtools.extended_keys import *
>>> M = XPrv.from_mnemonic('lemon child success once board usual cigar buffalo video cheese kitten onion build axis dose')
>>> M.encode()
b'xprv9s21ZrQH143K38p5ouMV2qFYest2F3uRQC51JPLqsdi8Lh1rkXUJRUy1m7rd5TvooJn6gerthNmntuJag6e73mrf8GmG96Ua8rpayQtUEsL'
```

Address Generation
```python
>>> (M/44./0./0./0/0).address('P2PKH')  # BIP44
b'1DgEh5Y6NioqaxHBBc2puDYq6SvG5NDsG9'
>>> (M/49./0./0./0/0).address('P2WPKH-P2SH')  # BIP49
b'39Qn8kHG6h7zv1Fh1iwjjyeRibx7gHTq1Z'
>>> (M/84./0./0./0/0).address('P2WPKH')  # BIP84
'bc1qrxxtlul9j3p95wrt33zg7vdf74skujnhnghaey'
```

## Run tests
```sh
python3 -m uninttest
```

## Run `setup.py`
```bash
python setup.py sdist bdist_wheel
```