import hashlib

# Example of ECDSA with secp256k1, the curve used in Bitcoin protocol
p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
F = GF(p)
a = 0
b = 7
E = EllipticCurve(F, [a, b])
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = E(Gx, Gy)
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

assert G.order() == q

def get_key_pair(priv = None):
    if priv is None:
        priv = randint(1, q-1)
    V = priv*G
    return V, priv

def sign(m, priv):
    # The hash function used in Bitcoin is SHA-256 applied twice, but here we use it once for demonstration purpose
    m = int(hashlib.sha256(m.encode()).hexdigest(), 16)
    e = randint(1, q-1)
    s1, _ = (e*G).xy()
    s1 = lift(s1) % q # lift() converts from modulo q to integer
    s2 = (m + priv * s1) * pow(e, -1, q) % q
    return s1, s2

def verify(m, V, s1, s2):
    m = int(hashlib.sha256(m.encode()).hexdigest(), 16)
    v1 = m * pow(s2, -1, q) % q
    v2 = s1 * pow(s2, -1, q) % q
    x_coor, _ = (lift(v1) * G + lift(v2) * V).xy()
    return lift(x_coor) % q == s1

V, priv = get_key_pair()
print('Verification point =', V)
print('Private key =', priv)

s1, s2 = sign("Let's meet at HKUST!", priv)
print('Signature =', s1, s2)

print("Original message: Let's meet at HKUST!")
print('Verification =', verify("Let's meet at HKUST!", V, s1, s2))

print("After message modification: Let's meet at KK Park!")
print('Verification =', verify("Let's meet at KK Park!", V, s1, s2))
