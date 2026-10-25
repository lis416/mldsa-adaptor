"""Exhaustive check of Lemma 1 (shift invariance of UseHint under condition C) for ML-DSA-44/65/87,
including the corner case of Decompose."""
import numpy as np, time
q = 8380417
for name, g2, eta in [('44', (q-1)//88, 2), ('65', (q-1)//32, 4), ('87', (q-1)//32, 2)]:
    alpha = 2*g2; m = (q-1)//alpha
    v = np.arange(q, dtype=np.int64)
    def decompose(r):
        rp = r % q
        r0 = rp % alpha; r0 = np.where(r0 > alpha//2, r0 - alpha, r0)
        corner = (rp - r0) == q-1
        r1 = np.where(corner, 0, (rp - r0)//alpha); r0 = np.where(corner, r0-1, r0)
        return r1, r0
    def usehint(h, r):
        r1, r0 = decompose(r)
        return np.where(h & (r0 > 0), (r1+1) % m, np.where(h & (r0 <= 0), (r1-1) % m, r1))
    t = time.time(); combos = 0; bad = 0
    r1v, r0v = decompose(v)
    for h in (0, 1):
        # condition C at this coefficient
        C = (np.abs(r0v) < g2 - eta)
        if h == 1: C &= ~((r0v > -eta) & (r0v <= eta))
        base = usehint(h, v)
        for r2 in range(-eta, eta+1):
            shifted = usehint(h, (v - r2) % q)
            combos += int(C.sum())
            bad += int((C & (shifted != base)).sum())
    print(f"ML-DSA-{name}: combinations satisfying C: {combos}, counterexamples: {bad}, {time.time()-t:.1f}s", flush=True)
    assert bad == 0, f"ML-DSA-{name}: {bad} counterexamples"

