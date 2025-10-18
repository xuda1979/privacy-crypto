from typing import Tuple

def encode_varint(n: int) -> bytes:
    """LEB128-like unsigned varint encoding."""
    if n < 0:
        raise ValueError("varint of negative value")
    out = bytearray()
    while True:
        to_write = n & 0x7F
        n >>= 7
        if n:
            out.append(to_write | 0x80)
        else:
            out.append(to_write)
            break
    return bytes(out)

def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Return (value, new_offset)."""
    shift = 0
    result = 0
    i = offset
    while True:
        if i >= len(data):
            raise ValueError("truncated varint")
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 63:
            raise ValueError("varint too large")
    return result, i
