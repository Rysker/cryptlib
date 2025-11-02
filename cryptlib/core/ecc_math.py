"""
Elliptic curve arithmetic and helper functions.

Provides modular inverse, Tonelli-Shanks square root, Point class,
and Curve class for scalar multiplication and point addition.
"""

from dataclasses import dataclass
from typing import Optional

def modinv(a: int, m: int) -> int:
    """Compute modular inverse of a modulo m."""
    if a == 0:
        raise ValueError("Inverse does not exist for 0")
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        r = high // low
        nm = hm - lm * r
        new = high - low * r
        hm, lm = lm, nm
        high, low = low, new
    return lm % m

def modular_sqrt(a: int, p: int) -> int:
    """Compute square root of a modulo p using Tonelli-Shanks algorithm."""
    if a == 0:
        return 0
    if p == 2:
        return a % 2
    ls = pow(a, (p - 1) // 2, p)
    if ls != 1:
        raise ValueError("No square root exists")
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)
    while True:
        if t == 0:
            return 0
        if t == 1:
            return r
        i = 1
        t2i = pow(t, 2, p)
        while t2i != 1:
            t2i = pow(t2i, 2, p)
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p
    return r

@dataclass
class Point:
    """Point on an elliptic curve."""
    x: Optional[int]
    y: Optional[int]

    def is_infinite(self) -> bool:
        """Check if the point is the point at infinity."""
        return self.x is None or self.y is None

class Curve:
    """Elliptic curve arithmetic for ECDSA operations."""
    def __init__(self, params):
        self.name = params.name
        self.p = params.p
        self.a = params.a
        self.b = params.b
        self.g = Point(params.gx, params.gy)
        self.n = params.n
        self.h = getattr(params, "h", 1)

    def is_on_curve(self, point: Optional[Point]) -> bool:
        """Check if a point is on the curve."""
        if point is None or point.is_infinite():
            return True
        return (point.y ** 2 - (point.x ** 3 + self.a * point.x + self.b)) % self.p == 0

    def point_add(self, p: Optional[Point], q: Optional[Point]) -> Optional[Point]:
        """Add two points on the curve."""
        if p is None or p.is_infinite():
            return q
        if q is None or q.is_infinite():
            return p
        if p.x == q.x and (p.y + q.y) % self.p == 0:
            return None
        if p.x == q.x:
            m = (3 * p.x * p.x + self.a) * modinv(2 * p.y, self.p) % self.p
        else:
            m = (q.y - p.y) * modinv(q.x - p.x, self.p) % self.p
        xr = (m * m - p.x - q.x) % self.p
        yr = (m * (p.x - xr) - p.y) % self.p
        return Point(xr, yr)

    def scalar_mult(self, k: int, p: Optional[Point] = None) -> Optional[Point]:
        """Multiply point p by scalar k on the curve."""
        if p is None:
            p = self.g
        if k % self.n == 0 or p is None:
            return None
        result = None
        addend = p
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result
