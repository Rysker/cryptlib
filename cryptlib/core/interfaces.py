"""
Interfaces for cryptographic primitives.

Defines abstract base classes for signatures, KEMs, and key generators.
"""
from abc import ABC, abstractmethod

class SignatureInterface(ABC):
    """Interface for digital signature."""
    @abstractmethod
    def generate_keypair(self):
        """Return (public_key_bytes, private_key_bytes)."""
        pass

    @abstractmethod
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign message and return signature bytes."""
        pass

    @abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature and return True if valid."""
        pass

class KEMInterface(ABC):
    """Interface for Key Encapsulation Mechanisms"""

    @abstractmethod
    def generate_keypair(self):
        """Return (public_key_bytes, private_key_bytes)."""
        pass

    @abstractmethod
    def encapsulate(self, public_key: bytes):
        """Return (ciphertext_bytes, shared_secret_bytes)."""
        pass

    @abstractmethod
    def decapsulate(self, private_key: bytes, ciphertext: bytes):
        """Return shared_secret_bytes from ciphertext and private key."""
        pass

class KeyPairGenerator(ABC):
    """Interface for key pair generators."""

    @abstractmethod
    def init(self, variant: str):
        """Initialize generator with specific variant."""
        pass

    @abstractmethod
    def generate_keypair(self):
        """Generate and return (public_key, private_key)."""
        pass

class ECDHInterface(ABC):
    """Interface for classical Elliptic Curve Diffie-Hellman key exchange."""

    @abstractmethod
    def generate_keypair(self):
        """Return (public_point, private_scalar)."""
        pass

    @abstractmethod
    def derive_shared_secret(self, private_scalar, peer_public_point):
        """Compute shared secret from private key and peer public key."""
        pass