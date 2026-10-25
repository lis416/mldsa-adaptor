"""Y = A r with ML-DSA-44's square matrix: recover r by linear algebra in the NTT domain."""
import numpy as np, time
q = 8380417; N = 256; k = l = 4; eta = 2
zeta = 1753  # primitive 512-th root of unity mod q (FIPS 204)
rng = np.random.default_rng(7)
roots = np.array([pow(zeta, 2*i+1, q) for i in range(N)], dtype=np.int64)   # roots of X^256+1
# evaluation matrix M[i,j] = roots[i]^j  (built column by column to avoid overflow)
M = np.ones((N, N), dtype=np.int64)
for j in range(1, N):
    M[:, j] = (M[:, j-1] * roots) % q
def ntt(p):  # p: (..., N) coefficient vectors -> evaluations at the 256 roots
    return (p @ M.T) % q      # (M @ p) for each vector
# inverse: p_j = (1/256) sum_i phat_i roots_i^{-j}
inv256 = pow(256, q-2, q)
Minv = np.ones((N, N), dtype=np.int64)
rinv = np.array([pow(int(r), q-2, q) for r in roots], dtype=np.int64)
for j in range(1, N):
    Minv[:, j] = (Minv[:, j-1] * rinv) % q
def intt(ph):
    return ((ph @ Minv) % q) * inv256 % q
def modpm(x): x = x % q; return np.where(x > q//2, x - q, x)

A = rng.integers(0, q, (k, l, N), dtype=np.int64)
r = rng.integers(-eta, eta+1, (l, N), dtype=np.int64)
# Y = A r computed via NTT (pointwise products)
Ah = ntt(A)            # (k, l, N)
rh = ntt(r % q)        # (l, N)
Yh = np.einsum('ijn,jn->in', Ah, rh) % q
t = time.time()
# solve 256 independent k x l systems over F_q by Gaussian elimination
sol = np.zeros((l, N), dtype=np.int64)
for n in range(N):
    Mn = [[int(Ah[i, j, n]) for j in range(l)] + [int(Yh[i, n])] for i in range(k)]
    # forward elimination
    row = 0
    for col in range(l):
        piv = next((i for i in range(row, k) if Mn[i][col] % q), None)
        if piv is None: continue
        Mn[row], Mn[piv] = Mn[piv], Mn[row]
        inv = pow(Mn[row][col], q-2, q)
        Mn[row] = [(x*inv) % q for x in Mn[row]]
        for i in range(k):
            if i != row and Mn[i][col]:
                f = Mn[i][col]; Mn[i] = [(a - f*b) % q for a, b in zip(Mn[i], Mn[row])]
        row += 1
    if row != l:
        raise RuntimeError(f"NTT component {n} is rank deficient; this sample does not meet the recovery condition")
    for j in range(l): sol[j, n] = Mn[j][l]
rec = modpm(intt(sol))
el = time.time() - t
assert np.array_equal(rec, r), "recovered witness differs from the sampled witness"
print("seed=7; full-rank NTT components=256/256; recovered == r:", np.array_equal(rec, r), f"  time {el*1000:.1f} ms")

