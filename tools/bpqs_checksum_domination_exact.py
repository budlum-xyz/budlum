#!/usr/bin/env python3
"""Exact checksum-side enumeration for the Budlum-BPQS domination hunt.

Companion to crates/bpqs/SECURITY-ARGUMENT.md section 6. The security
argument prices the few-time hunt with the three checksum digits treated
as uniform ("first-order estimate"). This script computes the checksum
side EXACTLY, so the only un-priced term left in the first-order
decomposition is the message-into-checksum cross-correlation (the
reviewer's formal refinement, question 1 of
docs/BPQS_INDEPENDENT_REVIEW_CALL.md).

Ground truth used here (must match crates/bpqs/src/params.rs):
 - LEN = 67 for any w = 16 row; 64 message digits + 3 checksum digits.
 - checksum T = sum_{j=1..64} (15 - m_j); since 15 - m_j is uniform on
   0..15 whenever m_j is, T is the sum of 64 iid uniform 0..15 digits.
 - checksum digit ranks: (T % 16, (T div 16) % 16, T div 256) - T < 1024
   for the any-w row, so rank 2 lives in 0..3 with probability 1.

Everything below is exact rational arithmetic through Python integers:
convolution gives the exact count of (m_1..m_64) tuples per T value.
"""

from fractions import Fraction

W = 16
MSG_DIGITS = 64
T_MAX = (W - 1) * MSG_DIGITS + 1  # 961 bins, T in 0..960


def checksum_dist():
    """Exact distribution of T = sum of MSG_DIGITS iid Uniform(0..W-1)."""
    counts = [1]  # count per partial sum
    for _ in range(MSG_DIGITS):
        nxt = [0] * (len(counts) + (W - 1))
        for s, c in enumerate(counts):
            for v in range(W):
                nxt[s + v] += c
        counts = nxt
    total = sum(counts)
    assert total == W**MSG_DIGITS and len(counts) == T_MAX
    return counts, total


def digits_of(t):
    return (t % W, (t // W) % W, t // (W * W))


def marginal(counts, total, rank):
    raw = [0] * W
    for t, c in enumerate(counts):
        raw[digits_of(t)[rank]] += c
    return [Fraction(c, total) for c in raw]


def e_min(marg, q):
    """E[min of q iid draws of the digit] = sum_{v>=1} P(D >= v)^q."""
    tail = [sum(marg[v:]) for v in range(W)]
    return sum(tail[v] ** q for v in range(1, W))


def domination_prob_pair(counts, total):
    """Exact P(C <= H digitwise) for two iid checksum vectors (q = 1)."""
    num, den = 0, total * total
    for t_c, c_c in enumerate(counts):
        dc = digits_of(t_c)
        for t_h, c_h in enumerate(counts):
            dh = digits_of(t_h)
            if all(dc[r] <= dh[r] for r in range(3)):
                num += c_c * c_h
    return Fraction(num, den)


def domination_prob_pair_q(counts, total, q_h):
    """P(candidate checksum digitwise <= min of q_h honest draws, each).

    min_{i<=q} digit_r >= v  <=>  all q draws have digit_r >= v; joint
    over the 3 ranks requires the honest joint distribution of the digit
    VECTOR, not just marginals. Honest joint: 4-tuple buckets of T.
    """
    # bucket honest draws by digit vector
    bucket = {}
    for t, c in enumerate(counts):
        d = digits_of(t)
        bucket[d] = bucket.get(d, 0) + c
    # reach(d): mass of honest vectors >= d componentwise
    reach = {}
    for d, _ in bucket.items():
        reach[d] = sum(
            c for e, c in bucket.items() if all(e[r] >= d[r] for r in range(3))
        )
    num = 0
    for d, c in bucket.items():
        # candidate digit vector d; probability the q-min dominates it
        p_min_ge = Fraction(reach[d], total) ** q_h
        num += c * p_min_ge
    return Fraction(num, total)


def fmt(x, nd=4):
    return f"{float(x):.{nd}f}"


def main():
    counts, total = checksum_dist()
    margs = [marginal(counts, total, r) for r in range(3)]
    unif = [Fraction(1, W) for _ in range(W)]
    msg_term_p = Fraction(17, 32)  # (8.5/16) per message digit, q=1 pair

    print("== exact checksum digit marginals (rank: values with nonzero mass) ==")
    for r, m in enumerate(margs):
        nz = {v: fmt(p, 6) for v, p in enumerate(m) if p > 0}
        print(f"  rank {r}: {nz}")
        print(f"  rank {r}: matches uniform exactly? {m == unif}")

    print("\n== E[min of q iid draws] per checksum rank (uniform compare) ==")
    for q in (1, 2, 4, 8):
        vals = [fmt(e_min(margs[r], q)) for r in range(3)]
        vals_u = fmt(e_min(unif, q))
        print(f"  q={q}: ranks {vals}  uniform {vals_u}")

    print("\n== checksum-side joint domination term ==")
    p1 = domination_prob_pair(counts, total)
    p1u = msg_term_p**3  # uniform first-order value
    print(f"  exact  P(C<=H over 3 ranks), q=1: {fmt(p1, 6)}  log2 {float(p1.numerator.bit_length()-p1.denominator.bit_length())}")
    print(f"  uniform first-order (17/32)^3:   {fmt(p1u, 6)}")
    for q in (1, 2, 4, 8):
        p = domination_prob_pair_q(counts, total, q)
        import math
        print(f"  q_honest={q}: exact P(C <= min over honest q, joint ranks) "
              f"= {fmt(p,6)}  log2 = {math.log2(float(p)):.3f}")

    print("\n== refined q=1 first-order work factor ==")
    import math
    msg_term = msg_term_p**MSG_DIGITS
    refined = msg_term * p1
    uniform_fs = msg_term * p1u
    print(f"  msg-position term (17/32)^64: log2 = {math.log2(float(msg_term)):.3f}")
    print(f"  exact checksum term:          log2 = {math.log2(float(p1)):.3f}")
    print(f"  refined total:                log2 = {math.log2(float(refined)):.3f}"
          f"   (first-order-uniform was {math.log2(float(uniform_fs)):.3f})")

    print("\n== rank-2 support check ==")
    hi = [t for t, c in enumerate(counts) if digits_of(t)[2] >= 4 and c > 0]
    print(f"  T values with rank2 digit >= 4 and positive mass: {len(hi)} (expect 0)")


if __name__ == "__main__":
    main()
