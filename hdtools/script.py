from hdtools.conversions import int_to_bytes


def op_push(i: int) -> bytes:
    """
    Push Operators
    https://en.bitcoin.it/wiki/Script#Constants
    """
    if i < 0x4c:
        return int_to_bytes(i)
    elif i < 0xff:
        return b'\x4c' + int_to_bytes(i)
    elif i < 0xffff:
        return b'\x4d' + int_to_bytes(i)
    else:
        return b'\x4e' + int_to_bytes(i)


def push(script: bytes) -> bytes:
    return op_push(len(script)) + script


def witness_byte(witver: int) -> bytes:
    assert 0 <= witver <= 16, "Witness version must be between 0-16"
    return int_to_bytes(witver + 0x50 if witver > 0 else 0)
