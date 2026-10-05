"""BLS12-381 curve arithmetic and optimal-ate pairing.

Self-contained pure-Python implementation with no third-party runtime
dependencies.  Formulas follow the well audited MIT-licensed py_ecc
reference implementation of BLS12-381.

Conventions:
* Fp elements are plain ints reduced modulo P.
* Fp2 elements are ``(c0, c1)`` with ``u**2 == -1``.
* Fp12 elements are 12-tuples with modulus ``t**12 - 2*t**6 + 2``
  (``w**6 == 1 + u``).
* G1/G2 points are Jacobian triples; ``Z == 0`` is the point at infinity.
* ``pairing(Q, P)`` takes Q in G2 and P in G1 and is bilinear:
  ``e(a*Q, P) == e(Q, a*P) == e(Q, P)**a``.
"""

from __future__ import annotations


P = (
    4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
)
R = 52435875175126190479447740508185965837690552500527637822603658699938581184513
ATE_LOOP_COUNT = 15132376222941642752
PSEUDO_BINARY = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1,
]


def fp_inv(a: int) -> int:
    return pow(a % P, -1, P)


def scalar_inv(a: int) -> int:
    return pow(a % R, -1, R)


# --------------------------------------------------------------------------
# Fp2: a + b*u, u**2 = -1
# --------------------------------------------------------------------------

Fp2 = tuple[int, int]
FP2_ONE: Fp2 = (1, 0)
FP2_ZERO: Fp2 = (0, 0)


def fp2(a: int = 0, b: int = 0) -> Fp2:
    return (a % P, b % P)


def f2_add(x: Fp2, y: Fp2) -> Fp2:
    return ((x[0] + y[0]) % P, (x[1] + y[1]) % P)


def f2_sub(x: Fp2, y: Fp2) -> Fp2:
    return ((x[0] - y[0]) % P, (x[1] - y[1]) % P)


def f2_neg(x: Fp2) -> Fp2:
    return ((-x[0]) % P, (-x[1]) % P)


def f2_mul(x: Fp2, y: Fp2) -> Fp2:
    x0, x1 = x
    y0, y1 = y
    return (
        (x0 * y0 - x1 * y1) % P,
        (x0 * y1 + x1 * y0) % P,
    )


def f2_scl(x: Fp2, k: int) -> Fp2:
    return ((x[0] * k) % P, (x[1] * k) % P)


def f2_inv(x: Fp2) -> Fp2:
    x0, x1 = x
    norm = fp_inv((x0 * x0 + x1 * x1) % P)
    return ((x0 * norm) % P, (-(x1 * norm)) % P)


def f2_conj(x: Fp2) -> Fp2:
    return (x[0], (-x[1]) % P)


def f2_pow(x: Fp2, n: int) -> Fp2:
    result = FP2_ONE
    base = x
    while n > 0:
        if n & 1:
            result = f2_mul(result, base)
        base = f2_mul(base, base)
        n >>= 1
    return result


# --------------------------------------------------------------------------
# Fp12
# --------------------------------------------------------------------------

Fp12 = tuple[int, ...]
FP12_ONE: Fp12 = (1,) + (0,) * 11
FP12_ZERO: Fp12 = (0,) * 12
FP12_TWO: Fp12 = (2,) + (0,) * 11

# Reduction for t**12 -> 2*t**6 - 2.  In the degree-by-degree loop the
# source degree is exp (12..22), so the targets are exp-6 and exp-12.


def f12_add(x: Fp12, y: Fp12) -> Fp12:
    return tuple((x[i] + y[i]) % P for i in range(12))


def f12_sub(x: Fp12, y: Fp12) -> Fp12:
    return tuple((x[i] - y[i]) % P for i in range(12))


def f12_neg(x: Fp12) -> Fp12:
    return tuple((-c) % P for c in x)


def f12_mul(x: Fp12, y: Fp12) -> Fp12:
    acc = [0] * 23
    for i in range(12):
        xi = x[i]
        if xi:
            for j in range(12):
                acc[i + j] = (acc[i + j] + xi * y[j]) % P
    for exp in range(22, 11, -1):
        top = acc[exp]
        if top:
            acc[exp - 6] = (acc[exp - 6] + 2 * top) % P
            acc[exp - 12] = (acc[exp - 12] - 2 * top) % P
        acc.pop()
    return tuple(acc)


def f12_sqr(x: Fp12) -> Fp12:
    return f12_mul(x, x)


def f12_inv(x: Fp12) -> Fp12:
    # Full norm via Frobenius (no manual tower repacking):
    #   n6 = x * x**(p**6) in Fp6
    #   n2 = n6 * n6**(p**2) * n6**(p**4) in Fp2
    #   x**-1 = x**(p**6)
    #          * n6**(p**4) * n6**(p**2) * n2**-1
    x_p6 = f12_frob6(x)
    n6 = f12_mul(x, x_p6)
    n6_p2 = f12_frob2(n6)
    n6_p4 = f12_frob2(n6_p2)
    norm_fp2 = f12_mul(f12_mul(n6, n6_p2), n6_p4)
    # The cubic norm lands in Fp[s] with s = w**6, s**2 = 2*s - 2
    # (slots 0 and 6 of this flat basis).  Conjugate a + b*s -> a - b*s,
    # norm a**2 + 2*b**2 - 2*a*b.
    a0, b0 = norm_fp2[0], norm_fp2[6]
    d = (a0 * a0 + 2 * a0 * b0 + 2 * b0 * b0) % P
    d_inv = fp_inv(d)
    norm_inv = (
        (a0 + 2 * b0) * d_inv % P, 0, 0, 0, 0, 0,
        (-b0) * d_inv % P, 0, 0, 0, 0, 0,
    )
    return f12_mul(
        f12_mul(x_p6, f12_mul(n6_p4, n6_p2)),
        norm_inv,
    )


def _fp6_inv_as_fp12(x: Fp12) -> Fp12:
    # Invert an element of the Fp6 subfield, exploiting the cubic norm so
    # the result is computed entirely in Fp2.  Fp6 is represented as
    # Fp2[v] / (v**3 - xi); multiplication keeps us inside Fp6, so we do
    # the arithmetic on structural Fp2 triples and map back to Fp12.
    a, b, c = fp6_parts(x)
    xi: Fp2 = (1, 1)
    a2 = f2_mul(a, a)
    b2 = f2_mul(b, b)
    c2 = f2_mul(c, c)
    t0 = f2_sub(a2, f2_mul(xi, f2_mul(b, c)))
    t1 = f2_sub(f2_mul(xi, c2), f2_mul(a, b))
    t2 = f2_sub(b2, f2_mul(a, c))
    det = f2_add(
        f2_mul(a, t0),
        f2_add(f2_mul(f2_mul(xi, c), t1), f2_mul(f2_mul(xi, b), t2)),
    )
    det_inv = f2_inv(det)
    return fp6_from_parts(
        f2_mul(t0, det_inv),
        f2_mul(t1, det_inv),
        f2_mul(t2, det_inv),
    )


def fp6_mul_triples(
    x: tuple[Fp2, Fp2, Fp2], y: tuple[Fp2, Fp2, Fp2]
) -> tuple[Fp2, Fp2, Fp2]:
    a, b, c = x
    d, e, f = y
    xi: Fp2 = (1, 1)
    t0 = f2_add(
        f2_mul(a, d),
        f2_add(f2_mul(f2_mul(b, f), xi), f2_mul(f2_mul(c, e), xi)),
    )
    t1 = f2_add(
        f2_add(f2_mul(a, e), f2_mul(b, d)),
        f2_mul(f2_mul(c, f), xi),
    )
    t2 = f2_add(
        f2_add(f2_mul(a, f), f2_mul(c, d)),
        f2_mul(b, e),
    )
    return t0, t1, t2


def fp6_parts(x: Fp12) -> tuple[Fp2, Fp2, Fp2]:
    # Fp6 embedding a + b*v + c*v**2 with v = w**2, and u = w**6 - 1.
    # Mapping monomial degree d to (v-power, u-power):
    #   w**0=1, w**2=v, w**4=v**2,
    #   w**6=1+u, w**8=v*(1+u), w**10=v**2*(1+u).
    # Hence the Fp2 c0 parts come from degrees 0/2/4 and the c1 parts
    # from degrees 6/8/10.
    return (x[0], x[6]), (x[2], x[8]), (x[4], x[10])


def fp6_from_parts(a: Fp2, b: Fp2, c: Fp2) -> Fp12:
    return (
        a[0], 0, b[0], 0, c[0], 0,
        a[1], 0, b[1], 0, c[1], 0,
    )


def f12_inv_generic(x: Fp12) -> Fp12:
    # Extended euclidean algorithm over Fp[t] / (t**12 - 2*t**6 + 2).
    # Kept only as a reference/test fallback; it is intentionally slow.
    modulus = [2, 0, 0, 0, 0, 0, -2, 0, 0, 0, 0, 0, 1]

    def deg(a: list[int]) -> int:
        i = len(a) - 1
        while i >= 0 and a[i] % P == 0:
            i -= 1
        return i

    lm = [1] + [0] * 12
    hm = [0] * 13
    low = list(x) + [0]
    high = list(modulus)
    while deg(low) > 0:
        dega, degb = deg(high), deg(low)
        r = [0] * 13
        temp = list(high)
        for i in range(dega - degb, -1, -1):
            r[degb + i] = temp[degb + i] * fp_inv(low[degb]) % P
            for c in range(degb + 1):
                temp[c + i] = (temp[c + i] - r[c + i] * low[c]) % P
        nm, new = list(hm), list(high)
        for i in range(13):
            for j in range(13 - i):
                nm[i + j] = (nm[i + j] - lm[i] * r[j]) % P
                new[i + j] = (new[i + j] - low[i] * r[j]) % P
        lm, low, hm, high = nm, new, lm, low
    scale = fp_inv(low[0])
    return tuple((lm[i] * scale) % P for i in range(12))


def f12_div(x: Fp12, y: Fp12) -> Fp12:
    return f12_mul(x, f12_inv(y))


def f12_pow(x: Fp12, n: int) -> Fp12:
    result = FP12_ONE
    base = x
    while n > 0:
        if n & 1:
            result = f12_mul(result, base)
        base = f12_mul(base, base)
        n >>= 1
    return result


def _build_frobenius_tables() -> tuple[tuple[Fp12, ...], Fp2, Fp2]:
    xi: Fp12 = tuple([0] * 6 + [1, 1] + [0] * 4)
    table = tuple(
        f12_pow(tuple([0] * i + [1] + [0] * (11 - i)), P)
        for i in range(12)
    )
    a = f12_pow(xi, (P - 1) // 3)
    b = f12_pow(xi, (P - 1) // 2)
    return table, (a[6], a[7]), (b[6], b[7])


_FROB_TABLE, G2_FROB_X, G2_FROB_X2 = _build_frobenius_tables()


def f12_frob(x: Fp12) -> Fp12:
    out = [0] * 12
    for i in range(12):
        xi = x[i]
        if xi:
            t = _FROB_TABLE[i]
            for j in range(12):
                if t[j]:
                    out[j] += xi * t[j]
    return tuple(v % P for v in out)


def f12_frob2(x: Fp12) -> Fp12:
    return f12_frob(f12_frob(x))


def f12_frob6(x: Fp12) -> Fp12:
    return tuple(c if i % 2 == 0 else (-c) % P for i, c in enumerate(x))


# --------------------------------------------------------------------------
# G1: y**2 = x**3 + 4 over Fp; G2: y**2 = x**3 + 4*(1+u) over Fp2
# --------------------------------------------------------------------------

G1Point = tuple[int, int, int]
G2Point = tuple[Fp2, Fp2, Fp2]
AnyPoint = G1Point | G2Point

B = 4
B2: Fp2 = (4, 4)

G1: G1Point = (
    3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507,
    1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569,
    1,
)
G2: G2Point = (
    fp2(
        352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160,
        3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758,
    ),
    fp2(
        1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905,
        927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582,
    ),
    FP2_ONE,
)


def is_inf(pt: AnyPoint) -> bool:
    return pt[2] == 0


def is_on_curve_g1(pt: G1Point) -> bool:
    if is_inf(pt):
        return True
    x, y, z = pt
    return (y * y * z - x * x * x) % P == (B * z * z * z) % P


def is_on_curve_g2(pt: G2Point) -> bool:
    if is_inf(pt):
        return True
    x, y, z = pt
    lhs = f2_sub(f2_mul(f2_mul(y, y), z), f2_mul(f2_mul(x, x), x))
    rhs = f2_mul(B2, f2_mul(f2_mul(z, z), z))
    return lhs == rhs


def point_double(pt: AnyPoint) -> AnyPoint:
    x, y, z = pt
    if type(x) is int:
        def mul(c, d):
            return (c * d) % P

        def scl(c, k):
            return (c * k) % P

        def sub(c, d):
            return (c - d) % P
        zero, one = 0, 1
    else:
        mul = f2_mul
        scl = f2_scl
        sub = f2_sub
        zero, one = FP2_ZERO, FP2_ONE
    w = scl(mul(x, x), 3)
    s = mul(y, z)
    bcoef = mul(mul(x, y), s)
    w2 = mul(w, w)
    h = sub(w2, scl(bcoef, 8))
    s2 = mul(s, s)
    return (
        scl(mul(h, s), 2),
        sub(
            mul(w, sub(scl(bcoef, 4), h)),
            scl(mul(mul(y, y), s2), 8),
        ),
        scl(mul(s, s2), 8),
    )


def point_add(p1: AnyPoint, p2: AnyPoint) -> AnyPoint:
    if type(p1[0]) is int:
        def mul(c, d):
            return (c * d) % P

        def scl(c, k):
            return (c * k) % P

        def sub(c, d):
            return (c - d) % P

        zero, one = 0, 1
    else:
        mul = f2_mul
        scl = f2_scl
        sub = f2_sub
        zero, one = FP2_ZERO, FP2_ONE
    if p1[2] == zero:
        return p2
    if p2[2] == zero:
        return p1
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    u1, u2 = mul(y2, z1), mul(y1, z2)
    v1, v2 = mul(x2, z1), mul(x1, z2)
    if v1 == v2:
        if u1 == u2:
            return point_double(p1)
        return (one, one, zero)
    u, v = sub(u1, u2), sub(v1, v2)
    v2v = mul(v, v)
    v3 = mul(v2v, v)
    v2v2 = mul(v2v, v2)
    w = mul(z1, z2)
    a = sub(sub(mul(mul(u, u), w), v3), scl(v2v2, 2))
    new_x = mul(v, a)
    new_y = sub(mul(u, sub(v2v2, a)), mul(v3, u2))
    new_z = mul(v3, w)
    return (new_x, new_y, new_z)


def point_mul(pt: AnyPoint, n: int) -> AnyPoint:
    n = n % R
    zero = 0 if type(pt[0]) is int else FP2_ZERO
    one = 1 if type(pt[0]) is int else FP2_ONE
    if n == 0:
        return (one, one, zero)
    result: AnyPoint = (one, one, zero)
    base = pt
    while n > 0:
        if n & 1:
            result = point_add(base, result)
        base = point_double(base)
        n >>= 1
    return result


def point_neg(pt: AnyPoint) -> AnyPoint:
    return (pt[0], -pt[1] if type(pt[0]) is int else f2_neg(pt[1]), pt[2])


def normalize_g1(pt: G1Point) -> G1Point:
    x, y, z = pt
    if z == 0:
        return (0, 1, 0)
    zi = fp_inv(z)
    # py_ecc projective convention: affine coordinates are (X/Z, Y/Z).
    return (x * zi % P, y * zi % P, 1)


def normalize_g2(pt: G2Point) -> G2Point:
    x, y, z = pt
    if z == FP2_ZERO:
        return (FP2_ZERO, FP2_ONE, FP2_ZERO)
    zi = f2_inv(z)
    return (f2_mul(x, zi), f2_mul(y, zi), FP2_ONE)


# --------------------------------------------------------------------------
# Twist isomorphism E'(Fp2) -> E(Fp12)
# --------------------------------------------------------------------------


def twist(pt: G2Point) -> tuple[Fp12, Fp12, Fp12]:
    _x, _y, _z = pt
    xc = (_x[0] - _x[1]) % P, _x[1]
    yc = (_y[0] - _y[1]) % P, _y[1]
    zc = (_z[0] - _z[1]) % P, _z[1]
    # Isomorphism into E(Fp12).  In Jacobian form the w**2 / w**3 divisions
    # for x/y are absorbed by taking z = w**3, so only X is shifted by one
    # degree while Y and Z keep their base placements.
    nx = tuple([0, xc[0]] + [0] * 5 + [xc[1]] + [0] * 4)
    ny = tuple([yc[0]] + [0] * 5 + [yc[1]] + [0] * 5)
    nz = tuple([0, 0, 0, zc[0]] + [0] * 5 + [zc[1], 0, 0])
    return (nx, ny, nz)


def cast_g1_to_f12(pt: G1Point) -> tuple[Fp12, Fp12, Fp12]:
    x, y, z = pt
    return (
        tuple([x] + [0] * 11),
        tuple([y] + [0] * 11),
        tuple([z] + [0] * 11),
    )


def g2_frob(pt: G2Point) -> G2Point:
    x, y, z = pt
    return (
        f2_mul((x[0] % P, (-x[1]) % P), G2_FROB_X),
        f2_mul((y[0] % P, (-y[1]) % P), G2_FROB_X2),
        f2_conj(z),
    )


# --------------------------------------------------------------------------
# Optimal-ate Miller loop (projective line evaluations, no inversions)
# --------------------------------------------------------------------------


def _line_num_den(
    p1: tuple[Fp12, Fp12, Fp12],
    p2: tuple[Fp12, Fp12, Fp12],
    t: tuple[Fp12, Fp12, Fp12],
) -> tuple[Fp12, Fp12]:
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    xt, yt, zt = t
    m_num = f12_sub(f12_mul(y2, z1), f12_mul(y1, z2))
    m_den = f12_sub(f12_mul(x2, z1), f12_mul(x1, z2))
    if m_den != FP12_ZERO:
        num = f12_sub(
            f12_mul(m_num, f12_sub(f12_mul(xt, z1), f12_mul(x1, zt))),
            f12_mul(m_den, f12_sub(f12_mul(yt, z1), f12_mul(y1, zt))),
        )
        den = f12_mul(f12_mul(m_den, zt), z1)
        return num, den
    if m_num == FP12_ZERO:
        m_num = f12_add(f12_mul(x1, x1), f12_mul(f12_mul(x1, x1), FP12_TWO))
        m_den = f12_mul(f12_add(y1, y1), z1)
        num = f12_sub(
            f12_mul(m_num, f12_sub(f12_mul(xt, z1), f12_mul(x1, zt))),
            f12_mul(m_den, f12_sub(f12_mul(yt, z1), f12_mul(y1, zt))),
        )
        den = f12_mul(f12_mul(m_den, zt), z1)
        return num, den
    return f12_sub(f12_mul(xt, z1), f12_mul(x1, zt)), f12_mul(z1, zt)


def miller_loop(q: G2Point, p: G1Point) -> Fp12:
    cast_p = cast_g1_to_f12(p)
    r_q = q
    twist_r = twist(r_q)
    twist_q = twist_r
    f_num = f_den = FP12_ONE
    for bit in PSEUDO_BINARY[62::-1]:
        num, den = _line_num_den(twist_r, twist_r, cast_p)
        f_num = f12_mul(f12_mul(f_num, f_num), num)
        f_den = f12_mul(f12_mul(f_den, f_den), den)
        r_q = point_double(r_q)
        twist_r = twist(r_q)
        if bit == 1:
            num, den = _line_num_den(twist_r, twist_q, cast_p)
            f_num = f12_mul(f_num, num)
            f_den = f12_mul(f_den, den)
            r_q = point_add(r_q, q)
            twist_r = twist(r_q)
    return f12_div(f_num, f_den)


def final_exponentiate(x: Fp12) -> Fp12:
    # Easy part: (p**6 - 1)(p**2 + 1)
    p2 = f12_mul(f12_frob2(x), x)
    p3 = f12_div(f12_frob(f12_frob(f12_frob(f12_frob(f12_frob(f12_frob(p2)))))), p2)
    cofactor = (P**4 - P**2 + 1) // R
    return f12_pow(p3, cofactor)


def pairing(q: G2Point, p: G1Point) -> Fp12:
    if not is_on_curve_g2(q):
        raise ValueError("point not on G2 curve")
    if not is_on_curve_g1(p):
        raise ValueError("point not on G1 curve")
    if is_inf(q) or is_inf(p):
        return FP12_ONE
    return final_exponentiate(miller_loop(q, p))


# --------------------------------------------------------------------------
# Serialization, validation and scalar hashing helpers
# --------------------------------------------------------------------------

import hashlib
import secrets


def random_scalar() -> int:
    return secrets.randbelow(R - 1) + 1


def hash_to_scalar(*parts: bytes) -> int:
    h = hashlib.sha256()
    h.update(len(parts).to_bytes(2, "big"))
    for part in parts:
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return int.from_bytes(h.digest(), "big") % R


def _fp_encode(v: int) -> bytes:
    return v.to_bytes(48, "big")


def _fp_decode(data: bytes) -> int:
    if len(data) != 48:
        raise ValueError("field element must be 48 bytes")
    v = int.from_bytes(data, "big")
    if v >= P:
        raise ValueError("field element out of range")
    return v


def g1_encode(pt: G1Point) -> bytes:
    x, y, _ = normalize_g1(pt)
    return b"\x01" + _fp_encode(x) + _fp_encode(y)


def g1_decode(data: bytes) -> G1Point:
    if len(data) != 97 or data[0] != 0x01:
        raise ValueError("bad G1 encoding")
    x = _fp_decode(data[1:49])
    y = _fp_decode(data[49:97])
    pt = (x, y, 1)
    if not is_on_curve_g1(pt):
        raise ValueError("G1 point not on curve")
    if normalize_g1(point_mul(pt, R))[:2] != (0, 1):
        raise ValueError("G1 point not in prime-order subgroup")
    return pt


def _fp2_encode(v: Fp2) -> bytes:
    return _fp_encode(v[0]) + _fp_encode(v[1])


def _fp2_decode(data: bytes) -> Fp2:
    return (_fp_decode(data[:48]), _fp_decode(data[48:96]))


def g2_encode(pt: G2Point) -> bytes:
    x, y, _ = normalize_g2(pt)
    return b"\x02" + _fp2_encode(x) + _fp2_encode(y)


def g2_decode(data: bytes) -> G2Point:
    if len(data) != 193 or data[0] != 0x02:
        raise ValueError("bad G2 encoding")
    x = _fp2_decode(data[1:97])
    y = _fp2_decode(data[97:193])
    pt = (x, y, FP2_ONE)
    if not is_on_curve_g2(pt):
        raise ValueError("G2 point not on curve")
    inf = normalize_g2(point_mul(pt, R))
    if inf != (FP2_ZERO, FP2_ONE, FP2_ZERO):
        raise ValueError("G2 point not in prime-order subgroup")
    return pt


def g1_generator_mul(n: int) -> G1Point:
    return point_mul(G1, n)


def g2_generator_mul(n: int) -> G2Point:
    return point_mul(G2, n)
