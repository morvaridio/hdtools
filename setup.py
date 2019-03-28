import setuptools
from distutils.core import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='hdtools',
    version='0.1.5',
    description='hd-tools for bitcoin and bitcoin-test',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Mahdi Fooladgar',
    author_email='fooladgar@morvarid.io',
    url='https://github.com/morvaridio/hdtools',
    license='MIT',
    packages=[
        'hdtools',
    ],
    keywords=["bip32", 'hd-wallet', 'bitcoin', 'bip49', 'bip44'],
    install_requires=[
        'ecdsa',
        'base58',
        'mnemonic'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',

        # Python versions
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
)
