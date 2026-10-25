#!/usr/bin/env python3
"""Certified upper bound using exact rank probabilities and directed Decimal rounding.

No Monte Carlo; no truncation of the 256-fold corank convolution.
All convolution inputs are upper bounds, all arithmetic is rounded upwards.
The emitted logarithms are descriptive only; the binary inequalities are checked.
"""
from decimal import Decimal, localcontext, ROUND_CEILING
from fractions import Fraction
import json

Q = 8380417

def corank_prob(dim, corank):
    rank = dim - corank
    p = Fraction(1, Q ** (corank * corank))
    for i in range(rank):
        p *= Fraction(Q**dim - Q**i, Q**dim) ** 2
        p /= Fraction(Q**rank - Q**i, Q**rank)
    return p

def calculate(dim, gamma1, gamma2, qh_log, cutoff=None):
    with localcontext() as ctx:
        ctx.prec = 450
        ctx.rounding = ROUND_CEILING
        probs_f = [corank_prob(dim, c) for c in range(dim + 1)]
        assert sum(probs_f) == 1
        probs = [Decimal(p.numerator) / Decimal(p.denominator) for p in probs_f]
        dist = [Decimal(1)]
        for _ in range(256):
            nxt = [Decimal(0)] * (len(dist) + dim)
            for j, x in enumerate(dist):
                for c, p in enumerate(probs):
                    nxt[j+c] += x * p
            dist = nxt
        base = (Decimal(2 * gamma2 + 1) / Decimal(2 * gamma1)) ** (256 * dim)
        total_rounds = 2**76  # 4096 * (2**63 + 2**63)
        prefactor = 2 * (2**qh_log + 1) * total_rounds + total_rounds**2
        def at(d):
            entropy = base * sum((dist[i] * Decimal(Q**i) for i in range(d+1)), Decimal(0))
            tail = sum(dist[d+1:], Decimal(0))
            upper = entropy * Decimal(prefactor) + tail
            return upper, entropy, tail
        d = cutoff if cutoff is not None else min(range(100), key=lambda x: at(x)[0])
        upper, entropy, tail = at(d)
        # Decimal(2) ** (-bits) is generally rounded at this precision.
        # Compare the exact rational value of our upper bound against the
        # exact binary threshold; an upward-rounded threshold is not a certificate.
        upper_exact = Fraction(upper)
        floor_bits = 0
        while upper_exact <= Fraction(1, 2 ** (floor_bits + 1)):
            floor_bits += 1
        assert upper_exact <= Fraction(1, 2 ** floor_bits)
        log2 = lambda x: float(x.ln() / Decimal(2).ln())
        return dict(ell=dim, cutoff=d, log2_entropy_upper=log2(entropy),
                    log2_tail_upper=log2(tail), log2_total_upper=log2(upper),
                    certified_bound=f"2^-{floor_bits}", precision=ctx.prec,
                    binary_comparison="exact rational", upper_decimal=str(upper))

if __name__ == '__main__':
    print(json.dumps({
        'formula': '[2(Q_H+1)L+L^2] epsilon_D + Pr[corank_sum>D]',
        'QS_log2': 63, 'QpS_log2': 63, 'caps': [4096, 4096],
        'results': [calculate(4, 2**17, (Q-1)//88, 128, 11),
                    calculate(5, 2**19, (Q-1)//32, 192),
                    calculate(7, 2**19, (Q-1)//32, 256)]
    }, ensure_ascii=False, indent=2))

