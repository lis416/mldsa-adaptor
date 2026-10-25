"""Instrument sign_generic with per-check rejection counters (applied to a temporary copy only)."""
import sys
p = sys.argv[1] + '/vendor/fips204/src/adaptor.rs'; s = open(p).read()
R = [
 ("use sha3::digest::XofReader;", "use sha3::digest::XofReader;\npub static REJ: [core::sync::atomic::AtomicU64; 6] = [const { core::sync::atomic::AtomicU64::new(0) }; 6];\nfn bump(i: usize) { REJ[i].fetch_add(1, core::sync::atomic::Ordering::Relaxed); }"),
 ("if z.iter().flat_map(|p| p.iter()).any(|x| x.abs() >= GAMMA1 - BETA - opts.zmarg) {\n            continue;", "if z.iter().flat_map(|p| p.iter()).any(|x| x.abs() >= GAMMA1 - BETA - opts.zmarg) {\n            bump(0); continue;"),
 ("if r0.iter().flat_map(|p| p.iter()).any(|x| x.abs() >= GAMMA2 - BETA - opts.r0marg) {\n            continue;", "if r0.iter().flat_map(|p| p.iter()).any(|x| x.abs() >= GAMMA2 - BETA - opts.r0marg) {\n            bump(1); continue;"),
 ("if norm_inf(&ct0) >= GAMMA2 {\n            continue;", "if norm_inf(&ct0) >= GAMMA2 {\n            bump(2); continue;"),
 ("if hint_weight(&h) > OMEGA {\n            continue;", "if hint_weight(&h) > OMEGA {\n            bump(3); continue;"),
 ("if !cond_c(&v, &h, b) {\n                continue;", "if !cond_c(&v, &h, b) {\n                bump(4); continue;"),
 ("return Ok((sig, round));", "bump(5); return Ok((sig, round));"),
]
for a, b in R:
    assert s.count(a) == 1, a; s = s.replace(a, b)
open(p, 'w').write(s)
