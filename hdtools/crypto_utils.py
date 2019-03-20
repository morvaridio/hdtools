import hashlib


def sha256(x):
    return hashlib.sha256(x).digest()


def sha512(x):
    return hashlib.sha512(x).digest()


def hash160(x):
    return hashlib.new('ripemd160', sha256(x)).digest()
