#!/usr/bin/env python3
"""Generate SPAKE2+ (RFC 9383) known-answer test vectors.

This is an *independent* reference implementation (pure-Python short-Weierstrass
EC arithmetic + the RFC 9383 transcript and key schedule) used to produce
exact key-share / shared-key vectors for curves the RFC does not cover
(P-384, P-521). It is self-validated against the RFC 9383 Appendix C P-256
HMAC vector before emitting any new vector, so agreement with the C
implementation is a genuine cross-implementation check rather than a
self-consistency check.

Run:  python3 tests/scripts/gen_spake2p_vectors.py

It prints, for each configured case, the hex of shareP, shareV and K_shared,
ready to paste into tests/suites/test_suite_spake2p.data (spake2p_kat).
"""

import hashlib
import hmac
import struct

# --- Short-Weierstrass NIST curves (y^2 = x^3 - 3x + b mod p) ---------------


class Curve:
    def __init__(self, name, p, b, gx, gy, n):
        self.name = name
        self.p = p
        self.a = p - 3
        self.b = b
        self.g = (gx, gy)
        self.n = n
        self.plen = (p.bit_length() + 7) // 8


P256 = Curve(
    "P-256",
    0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
)
P384 = Curve(
    "P-384",
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
    0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
    0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
    0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
    0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
)
P521 = Curve(
    "P-521",
    (1 << 521) - 1,
    0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
    0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
    0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
    6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449,
)


def inv_mod(x, p):
    return pow(x, p - 2, p)


def ec_add(c, p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % c.p == 0:
        return None
    if p1 == p2:
        m = (3 * x1 * x1 + c.a) * inv_mod(2 * y1, c.p) % c.p
    else:
        m = (y2 - y1) * inv_mod((x2 - x1) % c.p, c.p) % c.p
    x3 = (m * m - x1 - x2) % c.p
    y3 = (m * (x1 - x3) - y1) % c.p
    return (x3, y3)


def ec_mul(c, k, point):
    r = None
    addend = point
    while k:
        if k & 1:
            r = ec_add(c, r, addend)
        addend = ec_add(c, addend, addend)
        k >>= 1
    return r


def decompress(c, comp):
    """Decompress a SEC1 compressed point (0x02/0x03 || X)."""
    prefix = comp[0]
    x = int.from_bytes(comp[1:], "big")
    y2 = (x * x * x + c.a * x + c.b) % c.p
    # All three NIST primes are == 3 (mod 4), so sqrt = y2^((p+1)/4).
    y = pow(y2, (c.p + 1) // 4, c.p)
    if y % 2 != (prefix & 1):
        y = c.p - y
    return (x, y)


def point_uncompressed(c, point):
    x, y = point
    return b"\x04" + x.to_bytes(c.plen, "big") + y.to_bytes(c.plen, "big")


# --- RFC 9383 Section 4 constant points M and N (compressed) ----------------

MN = {
    "P-256": (
        bytes.fromhex(
            "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"),
        bytes.fromhex(
            "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"),
    ),
    "P-384": (
        bytes.fromhex(
            "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3d"
            "c36f15314739074d2eb8613fceec2853"),
        bytes.fromhex(
            "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543b"
            "b252c5490214cf9aa3f0baab4b665c10"),
    ),
    "P-521": (
        bytes.fromhex(
            "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d8560"
            "8cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa"),
        bytes.fromhex(
            "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b"
            "2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25"),
    ),
}

CURVES = {"P-256": P256, "P-384": P384, "P-521": P521}


def le64(n):
    return struct.pack("<Q", n)


def tt_field(data):
    return le64(len(data)) + data


def hkdf(hashmod, ikm, info, length):
    hlen = hashmod().digest_size
    prk = hmac.new(b"\x00" * hlen, ikm, hashmod).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashmod).digest()
        okm += t
        counter += 1
    return okm[:length]


def spake2p(curve_name, hashmod, context, id_prover, id_verifier, w0, w1, x, y):
    c = CURVES[curve_name]
    m_comp, n_comp = MN[curve_name]
    M = decompress(c, m_comp)
    N = decompress(c, n_comp)
    G = c.g

    w0 %= c.n
    w1 %= c.n

    # shareP = x*G + w0*M ; shareV = y*G + w0*N
    shareP = ec_add(c, ec_mul(c, x, G), ec_mul(c, w0, M))
    shareV = ec_add(c, ec_mul(c, y, G), ec_mul(c, w0, N))

    # Prover view: T = shareV - w0*N ; Z = x*T ; V = w1*T
    neg_w0N = ec_mul(c, (c.n - w0) % c.n, N)
    T = ec_add(c, shareV, neg_w0N)
    Z = ec_mul(c, x, T)
    V = ec_mul(c, w1, T)

    plen = c.plen
    tt = b""
    tt += tt_field(context)
    tt += tt_field(id_prover)
    tt += tt_field(id_verifier)
    tt += tt_field(point_uncompressed(c, M))
    tt += tt_field(point_uncompressed(c, N))
    tt += tt_field(point_uncompressed(c, shareP))
    tt += tt_field(point_uncompressed(c, shareV))
    tt += tt_field(point_uncompressed(c, Z))
    tt += tt_field(point_uncompressed(c, V))
    tt += tt_field(w0.to_bytes(plen, "big"))

    k_main = hashmod(tt).digest()

    # Confirmation keys: K_confirmP || K_confirmV = HKDF(K_main, "ConfirmationKeys").
    # For the HMAC ciphersuites the confirmation-key length equals the hash
    # length and the MAC is HMAC with the ciphersuite hash.
    conf_key_len = hashmod().digest_size
    conf = hkdf(hashmod, k_main, b"ConfirmationKeys", 2 * conf_key_len)
    k_confirm_p = conf[:conf_key_len]
    k_confirm_v = conf[conf_key_len:2 * conf_key_len]
    share_p_bytes = point_uncompressed(c, shareP)
    share_v_bytes = point_uncompressed(c, shareV)
    confirm_p = hmac.new(k_confirm_p, share_v_bytes, hashmod).digest()
    confirm_v = hmac.new(k_confirm_v, share_p_bytes, hashmod).digest()

    shared = hkdf(hashmod, k_main, b"SharedKey", hashmod().digest_size)

    return {
        "shareP": share_p_bytes,
        "shareV": share_v_bytes,
        "confirmP": confirm_p,
        "confirmV": confirm_v,
        "K_shared": shared,
    }


# --- RFC 9383 Appendix C P-256 HMAC vector (self-validation) ----------------


def selfcheck():
    context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors"
    w0 = int("bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3", 16)
    w1 = int("7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba", 16)
    x = int("d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539", 16)
    y = int("717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3", 16)
    exp_shareP = "04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb173300904" \
                 "2c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727"
    exp_shareV = "04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcade" \
                 "a75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048"
    exp_shared = "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7"

    # Validate every curve's domain parameters (p, a, b, G, n) at once: a
    # correct group order satisfies n*G = O (point at infinity).
    for c in (P256, P384, P521):
        assert ec_mul(c, c.n, c.g) is None, f"bad order for {c.name}"
    print("curve order check (n*G == O) for P-256/P-384/P-521: OK")

    exp_confirmP = "926cc71350 4b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527" \
                   .replace(" ", "")
    exp_confirmV = "9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68"

    r = spake2p("P-256", hashlib.sha256, context, b"client", b"server",
                w0, w1, x, y)
    assert r["shareP"].hex() == exp_shareP, r["shareP"].hex()
    assert r["shareV"].hex() == exp_shareV, r["shareV"].hex()
    assert r["confirmP"].hex() == exp_confirmP, r["confirmP"].hex()
    assert r["confirmV"].hex() == exp_confirmV, r["confirmV"].hex()
    assert r["K_shared"].hex() == exp_shared, r["K_shared"].hex()
    print("self-check against RFC 9383 P-256 HMAC vector "
          "(shares, confirms, K_shared): OK")


# Reuse the registration material already in test_suite_psa_crypto_pake.data so
# the KAT keys are consistent with the round-trip tests.
P384_W0 = int("097a61cbb1cee72bb654be96d80f46e0e3531151003903b572fc193f233772c2"
              "3c22228884a0d5447d0ab49a656ce1d2", 16)
P384_W1 = int("18772816140e6c3c3938a693c600b2191118a34c7956e1f1cd5b0d519b56ea58"
              "58060966cfaf27679c9182129949e74f", 16)
P521_W0 = int("009c79bcd7656716314fca5a6e2c5cda7ef86131399438e012a043051e863f60"
              "b5aeb3c101731e1505e721580f48535a9b0456b231b9266ae6fff49ee90d25f72f5f", 16)
P521_W1 = int("01632c15f51fcd916cd79e19075f8a69b72b0099922ad62ff8d540b469569f0a"
              "a027047aed2b3f242ea0ac4288b4e4db6a4e5946d8ad32b42192c5aa66d9ef8e1b33", 16)


def emit(name, curve_name, hashmod, w0, w1, x_hex, y_hex):
    c = CURVES[curve_name]
    x = int(x_hex, 16)
    y = int(y_hex, 16)
    assert 0 < x < c.n and 0 < y < c.n, "ephemeral out of range"
    r = spake2p(curve_name, hashmod, b"KAT context", b"client", b"server",
                w0, w1, x, y)
    print(f"\n--- {name} ---")
    print(f"x        = {x.to_bytes(c.plen, 'big').hex()}")
    print(f"y        = {y.to_bytes(c.plen, 'big').hex()}")
    print(f"shareP   = {r['shareP'].hex()}")
    print(f"shareV   = {r['shareV'].hex()}")
    print(f"K_shared = {r['K_shared'].hex()}")


if __name__ == "__main__":
    selfcheck()
    emit("P-384 HMAC-SHA384", "P-384", hashlib.sha384, P384_W0, P384_W1,
         "2a" * 48, "35" * 48)
    emit("P-521 HMAC-SHA512", "P-521", hashlib.sha512, P521_W0, P521_W1,
         "0001" + "23" * 64, "0001" + "45" * 64)
