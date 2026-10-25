# Environments

## A — main runs (run_seed20261002.md, run_seed777.md; timing table of the paper)
- DigitalOcean shared VM, 2 vCPU "DO-Regular" @ 2.0 GHz (AVX2 present; PQClean uses its AVX2 path), 2 GB RAM
- rustc 1.99.0 (b940084d7 2026-09-28), cargo 1.99.0
- release profile: opt-level=3, codegen-units=16, lto=off, no target-cpu flags; run under `nice 10`
  next to other live services, so timings are noisy (compare medians within a run)

## B — reproduction (reproduce_*.txt, noc_check_*.txt, reject_breakdown.txt, naive_mask.txt)
- Cloud VM, 2 vCPU Intel Xeon @ 2.10 GHz, 7 GB RAM
- rustc 1.97.0 (2d8144b78 2026-07-07)
- Same Cargo.lock (identical dependency versions), same profile

`cargo test --release` passes on both. `expt --seed 1 --n 500 --n-noc 2000 --n-filter 300 --n-det 50`
prints identical statistics on A and B, and noc_check reproduces exactly the failure counts of the
main runs (1256 and 1308): runs are deterministic given the seed.
