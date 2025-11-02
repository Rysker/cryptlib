"""
Factory for key pair generators in Cryptlib.

Provides a unified interface similar to Java KeyPairGenerator.
"""
from cryptlib.core.interfaces import KeyPairGenerator
from cryptlib.algorithms.ecdsa_signer import ECDSASigner
from cryptlib.algorithms.kyber_kem import KyberKEM
from cryptlib.algorithms.ecdh import ECDH

class KeyGeneratorFactory(KeyPairGenerator):
    """Factory to create key generators for ECC or Kyber."""
    def __init__(self, algorithm: str):
        self.algorithm = algorithm.upper()
        self.generator = None

    def init(self, variant: str):
        """Initialize generator with algorithm provided as the argument."""
        if self.algorithm == "ECDSA":
            self.generator = ECDSASigner(variant)
        elif self.algorithm == "ECDH":
            self.generator = ECDH(variant)
        elif self.algorithm == "KYBER":
            self.generator = KyberKEM(variant)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def generate_keypair(self):
        """Generate key pair using the initialized generator."""
        if self.generator is None:
            raise ValueError("Generator not initialized. Call init() first.")
        return self.generator.generate_keypair()
