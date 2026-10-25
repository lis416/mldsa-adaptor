# fips204 fork notes

Base: fips204 0.4.6 from crates.io (integritychain, MIT OR Apache-2.0), copied verbatim.

Changes (and nothing else):
1. `src/lib.rs`: added `pub mod adaptor;` after `pub mod traits;`.
2. `src/adaptor.rs`: new file — PreSign / PreVerify / Adapt / Extract / RGen and experiment helpers.
3. `Cargo.toml`: rewritten minimal manifest (dropped dev-dependencies/benches); same dependencies.

The original KeyGen / Sign / Verify code paths (ml_dsa.rs, lib.rs macros) are untouched;
adaptor.rs only calls existing `pub(crate)` helpers.
