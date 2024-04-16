# A detailed writeup is available at https://hackmd.io/@Jackylkk2003/Hyv5pCLlA

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from hashlib import sha256

Gx = 926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367
Gy = 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253
Ax = 6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997
Ay = 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696
Bx = 4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734
By = 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865

r1 = Gy ** 2 - Gx ** 3 - 726 * Gx
r2 = Ay ** 2 - Ax ** 3 - 726 * Ax
r3 = By ** 2 - Bx ** 3 - 726 * Bx

print(f'b = {r1} (mod p)')
print(f'b = {r2} (mod p)')
print(f'b = {r3} (mod p)')

p = gcd([r2 - r1, r3 - r1, r3 - r2])
print(f'p is a factor of {p}')

if is_prime(p):
    print(f'p = {p}')
else:
    print('p is not prime. Please factorize before proceeding.')
    exit()

b = r1 % p
print(f'b = {b} (mod p)')

F = GF(p)
E = EllipticCurve(F, [726, b])
G = E(Gx, Gy)
A = E(Ax, Ay)
B = E(Bx, By)

g_order = G.order()
print(g_order) # Output: 11

priv_a = 0
priv_b = 0
for i in range(g_order):
    if i * G == A:
        print(f'priv_a = {i}')
        priv_a = i
    if i * G == B:
        print(f'priv_b = {i}')
        priv_b = i

C = priv_a * B
secret = C[0]

print(C)

hash = sha256()
hash.update(long_to_bytes(lift(secret)))

key = hash.digest()[16:32]
iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = b'V\x1b\xc6&\x04Z\xb0c\xec\x1a\tn\xd9\xa6(\xc1\xe1\xc5I\xf5\x1c\xd3\xa7\xdd\xa0\x84j\x9bob\x9d"\xd8\xf7\x98?^\x9dA{\xde\x08\x8f\x84i\xbf\x1f\xab'
decrypted = cipher.decrypt(encrypted)
print(decrypted)
