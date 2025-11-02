"""
Deterministic nonce generator for ECDSA (RFC6979).

Generates a per-message deterministic 'k' from private key and message hash.
Supports hash functions from hashlib: sha256, sha384, sha512.
"""

import hmac
import hashlib
from typing import Callable

def bits2int(b: bytes, qlen: int) -> int:
    i = int.from_bytes(b, "big")
    blen = len(b) * 8
    if blen > qlen:
        i >>= (blen - qlen)
    return i

def int2octets(x: int, rolen: int) -> bytes:
    return x.to_bytes(rolen, "big")

def bits2octets(b: bytes, q: int, qlen: int) -> bytes:
    z1 = bits2int(b, qlen)
    z2 = z1 - q if z1 >= q else z1
    rolen = (qlen + 7) // 8
    return int2octets(z2, rolen)

def generate_k(hash_func: Callable[..., "hashlib._Hash"], q: int, x: int, h1: bytes) -> int:
    """Returns deterministic nonce k in range [1, q-1]"""
    qlen = q.bit_length()
    hlen = hash_func().digest_size
    rolen = (qlen + 7) // 8

    V = b"\x01" * hlen
    K = b"\x00" * hlen
    bx = int2octets(x, rolen) + bits2octets(h1, q, qlen)
    K = hmac.new(K, V + b"\x00" + bx, hash_func).digest()
    V = hmac.new(K, V, hash_func).digest()
    K = hmac.new(K, V + b"\x01" + bx, hash_func).digest()
    V = hmac.new(K, V, hash_func).digest()

    while True:
        T = b""
        while len(T) < rolen:
            V = hmac.new(K, V, hash_func).digest()
            T += V
        k = bits2int(T, qlen)
        if 1 <= k < q:
            return k
        K = hmac.new(K, V + b"\x00", hash_func).digest()
        V = hmac.new(K, V, hash_func).digest()
