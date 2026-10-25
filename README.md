# Paper artifact

This directory accompanies the English 2026-10-25 revision of *Compact Lattice-Based Adaptor Signatures Compatible with ML-DSA Verification*.

- `mldsa_adaptor/`: Rust ML-DSA-44 implementation, Cargo.lock, core tests, experiments and historical logs.
- `analysis/`: the three Python checks referenced by the paper.
- `probes/public_boundary.rs`: archived historical probe; the runnable version is `mldsa_adaptor/src/bin/public_boundary.rs`.

## Python checks

Use Python 3. The two NumPy scripts require NumPy; `capped_bound.py` uses only the standard library. Run from this directory:

```bash
python3 analysis/capped_bound.py
python3 analysis/naive_attack.py
python3 analysis/lemma1_check.py
```

`capped_bound.py` computes exact one-component corank probabilities, uses 450-digit upward Decimal rounding for the complete 256-fold convolution and direct tail sum, and compares the resulting upper bound with binary thresholds using exact rational arithmetic. Its logarithms are display values.

`naive_attack.py` samples a uniform 4-by-4 polynomial matrix with seed 7, checks that every NTT component has full rank, recovers the noiseless witness and asserts equality. This demonstrates the linear-algebra obstruction; it is not the naive-mask Rust diagnostic.

`lemma1_check.py` exhausts all residues, both hint bits and shifts in [-eta, eta] satisfying C for ML-DSA-44/65/87, including the special Decompose bucket. It prints exact combination counts and fails if any counterexample is found. The unchunked NumPy implementation uses substantial memory; the 2026-10-25 validation runs on a separate environment with an 8 GiB memory limit, not the 2 GiB experiment host.

Fresh Python outputs and environment/source hashes are in `analysis/results/`. These checks do not establish QROM security, actual-mask security, a uniform uncapped tail bound, or the hardness of additional lattice instances.

## Separate experiment batches

| Batch | Seed | Evidence |
|---|---:|---|
| Principal Rust runs | 20261002, 777 | `mldsa_adaptor/results/run_seed*.md` |
| Naive-mask diagnostic | 20261008 | `mldsa_adaptor/results/naive_mask.txt` |
| Public boundary probe | 20261019 | `mldsa_adaptor/results/public_boundary_*` |
| Noiseless recovery | 7 | `analysis/results/naive_attack_20261025.txt` |

The public probe is a separate 20,000-pair experiment. Preserve historical logs when recording a fresh reproduction. Exact source revisions and commands belong in the validation manifests; do not identify a modified working tree by its base commit alone.

## Publication status

Before public release, the author must select a project license and replace the paper's repository placeholder with a real URL. Third-party fips204 license files remain in the vendor directory. The core implementation only covers ML-DSA-44; the Python shift check covers all three parameter sets.
