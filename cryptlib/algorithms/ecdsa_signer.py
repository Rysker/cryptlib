"""
ECDSA signer and verifier implementation.

Uses arbitrary NIST curves (P-256, P-384, P-521) from core.ecc_parameters
and deterministic nonce per RFC6979 (deterministic_nonce).
"""

import hashlib
from cryptlib.core.interfaces import SignatureInterface
from cryptlib.core.ecc_parameters import get_curve
from cryptlib.core.ecc_math import Curve, Point, modinv
from .deterministic_nonce import generate_k

class ECDSASigner(SignatureInterface):
    """ECDSA signing and verification for NIST curves."""
    def __init__(self, curve_name: str = "P-256"):
        self.curve_params = get_curve(curve_name)
        self.curve = Curve(self.curve_params)
        self.hash_func = hashlib.sha256 if curve_name == "P-256" else (
            hashlib.sha384 if curve_name == "P-384" else hashlib.sha512
        )

    def generate_keypair(self):
        """Generate (public_key_bytes, private_key_bytes)."""
        import os
        private_key = int.from_bytes(os.urandom(self.curve_params.n.bit_length() // 8 + 8), "big") % self.curve.n
        public_point = self.curve.scalar_mult(private_key)
        public_key = public_point.x.to_bytes((public_point.x.bit_length() + 7)//8, "big") + \
                     public_point.y.to_bytes((public_point.y.bit_length() + 7)//8, "big")
        private_bytes = private_key.to_bytes((self.curve.n.bit_length() + 7)//8, "big")
        return public_key, private_bytes

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign a message using ECDSA and deterministic nonce."""
        z = int.from_bytes(self.hash_func(message).digest(), "big")
        d = int.from_bytes(private_key, "big")
        k = generate_k(self.hash_func, self.curve.n, d, self.hash_func(message).digest())
        R = self.curve.scalar_mult(k)
        r = R.x % self.curve.n
        s = (modinv(k, self.curve.n) * (z + r * d)) % self.curve.n
        r_bytes = r.to_bytes((r.bit_length()+7)//8, "big")
        s_bytes = s.to_bytes((s.bit_length()+7)//8, "big")
        return r_bytes + s_bytes

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an ECDSA signature."""
        r_len = s_len = len(signature)//2
        r = int.from_bytes(signature[:r_len], "big")
        s = int.from_bytes(signature[r_len:], "big")
        z = int.from_bytes(self.hash_func(message).digest(), "big")
        x_bytes = public_key[:len(public_key)//2]
        y_bytes = public_key[len(public_key)//2:]
        pub_point = Point(int.from_bytes(x_bytes, "big"), int.from_bytes(y_bytes, "big"))
        if not self.curve.is_on_curve(pub_point):
            return False
        w = modinv(s, self.curve.n)
        u1 = (z * w) % self.curve.n
        u2 = (r * w) % self.curve.n
        point = self.curve.point_add(self.curve.scalar_mult(u1), self.curve.scalar_mult(u2, pub_point))
        if point is None:
            return False
        return (point.x % self.curve.n) == r
