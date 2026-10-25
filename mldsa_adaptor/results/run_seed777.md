# ML-DSA-44 adaptor signature — §5.2 experiments (Rust)

seed = 777, N = 100000, N_noC = 200000, N_filter = 50000, N_det = 10000, N_time = 1000

## 1 / 8. Correctness: PreSign → PreVerify → Adapt → unmodified FIPS 204 Verify → Extract
PreVerify accepted: 100000/100000 = 100.000% [95% CI 99.996%, 100.000%]
adapted signature accepted by fips204-0.4.6 (unmodified Verify): 100000/100000 = 100.000% [95% CI 99.996%, 100.000%]
adapted signature accepted by RustCrypto ml-dsa 0.1.1: 100000/100000 = 100.000% [95% CI 99.996%, 100.000%]
adapted signature accepted by PQClean via pqcrypto-mldsa 0.1.2: 100000/100000 = 100.000% [95% CI 99.996%, 100.000%]
Extract returned exactly (r1, r2): 100000/100000 = 100.000% [95% CI 99.996%, 100.000%]
(half the trials with ctx = "5.2-ctx", one quarter of PreSigns deterministic; max PreSign rounds seen = 61, cap = 4096)

## 3. Rounds per signature
ML-DSA Sign rounds: 4.3563 ± 0.0237
PreSign rounds:     4.5768 ± 0.0251
PreSign / Sign = 1.0506  (extra +5.06%)

## 4. Unlinkability distinguishers (adversary knows r1, r2)
fresh ML-DSA signatures — D1 (‖z − r1‖∞ ≥ γ1−β−η): 1626/100000 = 1.626% [95% CI 1.549%, 1.706%]
fresh ML-DSA signatures — D2 (C(Az − c t1 2^d + r2, h) = 0): 2564/100000 = 2.564% [95% CI 2.468%, 2.664%]
fresh ML-DSA signatures — D1 ∪ D2: 4141/100000 = 4.141% [95% CI 4.019%, 4.266%]
adapted signatures — D1: 0, D2: 0  (must be 0 of 100000)
[info] D3 (needs t0; ‖LowBits(Az − c t)‖∞ ≥ γ2−β): fresh 0/100000 = 0.000% [95% CI 0.000%, 0.004%] | adapted 610/100000 = 0.610% [95% CI 0.564%, 0.660%]

## 2. Necessity of C (C removed from both PreSign and PreVerify)
passed PreVerify-without-C but adapted signature rejected by Verify: 1308/200000 = 0.654% [95% CI 0.620%, 0.690%]
(rejections per verifier: fips204 1308, RustCrypto 1308, PQClean 1308 — must agree)

## 5. Filtered variant (§4.5)
Sign rounds 4.3614 ± 0.0335 | Sign′ rounds 4.8227 ± 0.0378 | Sign′/Sign = 1.1058 (extra +10.58%)
FilterAdapt rejection rate: 3050/53050 = 5.749% [95% CI 5.554%, 5.951%]
filtered adapted signatures accepted by all three verifiers: 50000/50000 = 100.000% [95% CI 99.992%, 100.000%]
distinguishers on fresh Sign′: D1′ 0, D2′ 0, D3′ 0 | on FilterAdapt output: D1′ 0, D2′ 0, D3′ 0  (all must be 0 of 50000)

## 6. Deterministic-mode self-check (same M, two different Y, rnd = 0)
min over 10000 pairs of ‖ẑ − ẑ′‖∞ = 235423  (a leak would make this ≤ 2β = 156); same (M, Y) reproduced bit-exactly: 10000/10000

## 7. Timing (median over 1000 runs each, µs; all from byte-encoded keys, i.e. including key decoding and ExpandA)
| operation | median µs | mean µs |
|---|---:|---:|
| KeyGen | 209.7 | 225.4 |
| Sign (fips204, unmodified) | 552.2 | 674.0 |
| Sign (generic loop, same code as PreSign) | 479.4 | 599.7 |
| Verify (fips204, unmodified) | 159.3 | 174.1 |
| PreSign | 518.7 | 631.6 |
| PreVerify | 172.4 | 188.5 |
| Adapt (incl. PreVerify) | 189.5 | 206.5 |
| Extract | 146.0 | 159.2 |
| RGen | 148.3 | 163.9 |
| Verify (RustCrypto) | 154.3 | 166.1 |
| Verify (PQClean) | 57.2 | 61.3 |

total wall time 830.7 s
