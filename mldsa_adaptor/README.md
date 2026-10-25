# mldsa_adaptor — Rust implementation of the ML-DSA-compatible adaptor signature

PreSign / PreVerify / Adapt / Extract / RGen on top of FIPS 204 ML-DSA-44, and the experiments of
§5.2 of the paper ("Compact Lattice-Based Adaptor Signatures Compatible with ML-DSA Verification", English revision of 2026-10-25).

Research prototype: not optimized, not designed or evaluated for constant-time execution, not audited.

## Layout
- `vendor/fips204/` — fips204 0.4.6 (integritychain, MIT OR Apache-2.0) copied verbatim, plus one new
  module `src/adaptor.rs` and one `pub mod adaptor;` line. KeyGen/Sign/Verify untouched;
  see `vendor/fips204/FORK_NOTES.md`.
- `src/lib.rs` — key generation (unmodified FIPS 204 KeyGen), the three verifiers, statistics helpers.
- `tests/core.rs` — correctness tests.
- `src/bin/expt.rs` — the two principal §5.2 runs; `src/bin/noc_check.rs` — re-runs the "necessity of C"
  experiment with the same seed and checks that every failing pre-signature is rejected by PreVerify with C.
- `tools/` — two diagnostics that need a *patched* copy of the code; `tools/run_tool.sh <name>` copies
  the crate to a temporary directory, patches it there and runs the tool (the main tree is never modified):
  - `reject_breakdown` — per-check pass rates of Sign and PreSign;
  - `naive_mask` — Remark 2 attack: with ρ″ = H(K‖rnd‖µ) (Y not hashed), deterministic pre-signatures on
    the same message under two statements leak (c − c′)s1.
- `src/bin/public_boundary.rs` — the separate public one-sided boundary test of §4.7 (seed 20261019, 20,000 pairs).
- `results/` — raw outputs; `results/ENV.md` describes the two machines.

## Verifiers (adapted signatures are checked by all three, none modified)
1. fips204 0.4.6 `Verify` (same crate as the primary implementation, untouched code path)
2. RustCrypto `ml-dsa` 0.1.1 (independent pure-Rust code base)
3. PQClean ML-DSA-44 via `pqcrypto-mldsa` 0.1.2 (independent C code base)

## Spec decisions
- **A per key** (Remark 1): RGen and PreVerify use A = ExpandA(ρ) of the signer's vk.
- **RGen**: (r1, r2) = ExpandS(seed) with a 64-byte seed (same sampler as s1, s2), Y = A r1 + r2 canonical.
- **encY** (k·256 coefficients, 23 bits each, 2944 bytes): coefficient j of polynomial i occupies bit
  positions 23·(256i + j) … +22; bit p is bit (p mod 8), LSB first, of byte ⌊p/8⌋ — the FIPS 204
  IntegerToBits/BitsToBytes order. Decoding rejects any coefficient ≥ q.
- **Mask seed**: ρ″ = H(K ‖ rnd ‖ µ ‖ encY, 64); µ = H(tr ‖ 0x00 ‖ |ctx| ‖ ctx ‖ M, 64).
- **Iteration cap**: 4096 *rounds* (κ advances by ℓ per round); exceeding it returns `Err(IterationCap)`.
- **Order of checks in PreSign**: z/r0 box → ‖c t0‖ → hint weight → C. Same accept set as the paper.
- **Adapt API guard (Algorithm 3)**: a witness with ‖r1‖∞ > η is rejected, so z = ẑ + r1 always
  satisfies the sigEncode precondition. Valid RGen witnesses are never affected.
- **Extract** compares c̃ first, then r1 = z − ẑ (exact integers), r2 = Y − A r1 (centered), checks
  ‖r1‖∞ < 261988, ‖r2‖∞ ≤ 380930. Any input that does not sigDecode is rejected.
- **Filtered variant (§4.7)**: Sign′ = generic loop with (zmarg, r0marg, C-margin) = (2η, η, 2η);
  FilterAdapt = Adapt then (T1)–(T3); T2 needs t0.

## Tests (`cargo test --release`; also run in debug with all fips204 debug_asserts on)
- ring multiplication == schoolbook negacyclic convolution;
- encY round trip, bit order, rejection of non-residues;
- generic loop with Y = None is **byte-identical** to fips204's own Sign (200 trials, ctx and rnd varied);
- full protocol, 300 trials: adapted σ accepted by all three verifiers, Extract == (r1, r2);
- digest check in Extract, PreVerify rejects other Y / other M, Adapt rejects tampered σ̂;
- deterministic mode: two different Y → ẑ − ẑ′ not short; same (M, Y) → identical bytes.

## Reproducing §5.2
    cargo build --release --locked
    ./target/release/expt --seed 20261002 --n 100000 --n-noc 200000 --n-filter 50000 --n-det 10000 --n-time 2000
    ./target/release/expt --seed 777      --n 100000 --n-noc 200000 --n-filter 50000 --n-det 10000 --n-time 1000
    ./target/release/noc_check 20261002 200000; ./target/release/noc_check 777 200000
    tools/run_tool.sh reject_breakdown; tools/run_tool.sh naive_mask
Each `expt` run takes about 15 minutes on 2 vCPUs. Every trial: fresh key (FIPS 204 KeyGen from a
ChaCha20 stream seeded by `--seed`), fresh statement, fresh 32-byte message. Item seeds are seed, seed+2,
seed+5, seed+6, seed+7. The paper pools the two main seeds. The naive-mask diagnostic uses a separate seed, 20261008; the public boundary probe uses 20261019.

## Results (two main seeds; final row is a separate diagnostic)
| item | result |
|---|---|
| adapted σ accepted by each verifier; Extract == (r1, r2) | 200000/200000 |
| Sign / PreSign iterations | 4.364 ± 0.017 / 4.569 ± 0.018 (+4.7% ± 0.6%) |
| without C: pass PreVerify, fail Verify | 2564/400000 = 0.64%; all rejected by PreVerify with C |
| distinguishers on fresh σ: D1 / D2 / D1∪D2 | 1.58% / 2.60% / 4.13%; on adapted σ: 0 |
| t0-based distinguisher on adapted σ | 0.64% |
| filtered: Sign′ extra iterations / FilterAdapt rejection | +10.8% ± 0.9% / 5.75% |
| filtered: distinguishers on either side | 0 of 10^5 |
| deterministic mode: min ‖ẑ − ẑ′‖∞ over 2·10^4 pairs | 235423 |
| naive mask derivation (Remark 2, seed 20261008): short differences equal to (c − c′)s1 | 4980/20000; recovery itself was not implemented |


## Public boundary test (§4.7)

Run from this crate:

```bash
cargo test --release --locked
cargo run --release --locked --bin public_boundary
```

The probe keeps the historical RNG call sequence: seed 20261019, 20,000 fresh-key pairs, empty context and hedged randomness. Its predicate receives only the public key and signature; it does not use the witness or t0. The historical counts are 106/20000 fresh signatures (0.530%, Wilson 95% [0.4384%, 0.6406%]) and 0/20000 adapted signatures. See `results/public_boundary_PROVENANCE.md` for the original report and new-run records.

This measures one public test, not an upper bound on arbitrary distinguishers. The probe uses the generic signing loop as the fresh baseline; the core tests separately check byte equality with fips204 signing and interoperability with three verifiers.

## Python analysis and publication scope

The companion scripts are in `../analysis/`, with instructions in `../README.md`; they are part of the paper artifact and should be published together with this crate. Internal API names `Y` and `encY` denote the paper's statement R and its canonical encoding. They are retained for compatibility with the historical code.

The prototype implements ML-DSA-44 only. A project-level license still needs to be selected by the author; the vendored fips204 MIT and Apache-2.0 notices are retained.
