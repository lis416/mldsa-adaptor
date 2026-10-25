"""Replace the mask derivation by the NAIVE one of ML-DSA (Y not hashed) — Remark 2 attack demo.
Applied to a temporary copy only; never use this for anything else."""
import sys
p = sys.argv[1] + '/vendor/fips204/src/adaptor.rs'; s = open(p).read()
a = "h256_xof(&[&sk.cap_k, rnd, &mu, &enc]).read(&mut rho2);"
assert s.count(a) == 1
open(p, 'w').write(s.replace(a, "let _ = enc; h256_xof(&[&sk.cap_k, rnd, &mu]).read(&mut rho2); // NAIVE: Y not in the derivation"))
