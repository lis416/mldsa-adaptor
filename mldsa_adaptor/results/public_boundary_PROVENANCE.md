# Public boundary experiment provenance

The original probe was run on 2026-10-19 against standalone Rust commit `732e5f8cb0c24fff662905dd363ac0a62b87837c`. It uses ML-DSA-44, seed 20261019, 20,000 fresh-key/message/statement pairs, empty context and hedged randomness.

`public_boundary_seed20261019_historical.txt` reproduces stdout recorded in the appendix of `review_rev_20261019.md`; it is not a new run or a separately recovered raw process log. The historical probe, including its archive comments, remains at `../../probes/public_boundary.rs`. The runnable `src/bin/public_boundary.rs` preserves its executable body and RNG order.

The predicate reads only the public key and signature. Witnesses are used to generate adapted samples, not to evaluate the boundary test; t0 is not an input. The fresh baseline uses `ad::sign_counting`. The probe does not itself run all three verifiers; the core suite verifies compatibility separately.

Observed historical counts: fresh 106/20000 (0.530%, Wilson 95% [0.438435%, 0.640565%]); adapted 0/20000. This is an estimate for this specific public test under this sampling setup, not a bound on the best public attack. The paper proves that adapted signatures cannot trigger the predicate.

Any new run is recorded in a separately named output file with a manifest of commands, source commit/hashes, toolchain and exit status. The historical record is retained unchanged.

## Reproduction on 2026-10-25

Source commit: `159235d71a1cf71d8a94d2e8c7b81720f1d5ecf8`. Both `cargo test --release --locked --offline` (8 core tests) and `cargo run --release --locked --offline --bin public_boundary` exited successfully. The output line matches the historical record byte for byte.

See `cargo_test_release_20261025.txt`, `public_boundary_seed20261019_rerun_20261025.txt` and `validation_20261025.json` for the recorded commands, toolchain, source hashes and exit codes. This is a same-seed reproducibility check, not an additional independent sample to pool with the historical batch.
