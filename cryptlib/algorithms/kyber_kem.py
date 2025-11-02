"""
Wrapper for post-quantum CRYSTALS-Kyber Key Encapsulation Mechanism (KEM).

Supports Kyber-512, Kyber-768, Kyber-1024 using external pqcrypto library.
All keys and ciphertexts are in bytes.
"""

from cryptlib.core.interfaces import KEMInterface
import pqcrypto.kem.ml_kem_512 as kyber512
import pqcrypto.kem.ml_kem_768 as kyber768
import pqcrypto.kem.ml_kem_1024 as kyber1024

KYBER_MAP = {
    "Kyber-512": kyber512,
    "Kyber-768": kyber768,
    "Kyber-1024": kyber1024
}

class KyberKEM(KEMInterface):
    """KEM wrapper for CRYSTALS-Kyber."""

    def __init__(self, variant: str):
        # Initialize KEM with a specific Kyber variant
        if variant not in KYBER_MAP:
            raise ValueError(f"Unsupported Kyber variant: {variant}")
        self.kem = KYBER_MAP[variant]

    def generate_keypair(self) -> tuple[bytes, bytes]:
        # Returns public and private key in bytes
        pk, sk = self.kem.generate_keypair()
        return pk, sk

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        # Returns ciphertext and shared secret for given public key
        ciphertext, shared_secret = self.kem.encrypt(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        # Returns shared secret from private key and received ciphertext
        return self.kem.decrypt(private_key, ciphertext)
