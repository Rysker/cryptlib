"""
Elliptic Curve Diffie-Hellman (ECDH) key exchange.

Generates keypair on NIST curves (P-256, P-384, P-521)
and derives shared secret from private and public key.
"""

import secrets
from cryptlib.core.ecc_parameters import CURVES
from cryptlib.core.ecc_math import Curve, Point
from cryptlib.core.interfaces import ECDHInterface

class ECDH(ECDHInterface):
    """ECDH key exchange using NIST defined curves."""
    def __init__(self, curve_name: str):
        if curve_name not in CURVES:
            raise ValueError(f"Unsupported curve: {curve_name}")
        self.params = CURVES[curve_name]
        self.curve = Curve(self.params)

    def generate_keypair(self):
        """Returns public and private key"""
        private_scalar = secrets.randbelow(self.curve.n - 1) + 1
        public_point = self.curve.scalar_mult(private_scalar)
        return public_point, private_scalar

    def derive_shared_secret(self, private_scalar: int, peer_public_point: Point):
        """Returns shared secret"""
        shared_point = self.curve.scalar_mult(private_scalar, peer_public_point)
        if shared_point is None or shared_point.is_infinite():
            raise ValueError("Invalid shared point")
        return shared_point.x
