//! §5.2 experiments. Usage:
//!   expt [--seed S] [--n N] [--n-noc N2] [--n-filter N3] [--n-det N4] [--n-time T] [--out FILE]
//! Every trial uses a fresh key (unmodified FIPS 204 KeyGen from a seeded ChaCha20 stream),
//! a fresh statement (RGen), a fresh 32-byte message and hedged rnd unless stated otherwise.
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use mldsa_adaptor::ad::{self, PolyVec, SignOpts};
use mldsa_adaptor::*;
use std::fmt::Write as _;
use std::time::Instant;

struct Args { seed: u64, n: u64, n_noc: u64, n_filter: u64, n_det: u64, n_time: usize, out: Option<String> }

fn parse() -> Args {
    let mut a = Args { seed: 20261002, n: 10_000, n_noc: 100_000, n_filter: 10_000, n_det: 1_000, n_time: 1_000, out: None };
    let v: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--seed" => a.seed = val.parse().unwrap(),
            "--n" => a.n = val.parse().unwrap(),
            "--n-noc" => a.n_noc = val.parse().unwrap(),
            "--n-filter" => a.n_filter = val.parse().unwrap(),
            "--n-det" => a.n_det = val.parse().unwrap(),
            "--n-time" => a.n_time = val.parse().unwrap(),
            "--out" => a.out = Some(val),
            x => panic!("unknown arg {x}"),
        }
        i += 2;
    }
    a
}

fn sub(a: &PolyVec, b: &PolyVec) -> PolyVec { core::array::from_fn(|i| core::array::from_fn(|n| a[i][n] - b[i][n])) }
fn add_mod(a: &PolyVec, b: &PolyVec) -> PolyVec {
    core::array::from_fn(|i| core::array::from_fn(|n| (a[i][n] + b[i][n]).rem_euclid(ad::MODULUS)))
}
fn exact_norm(v: &PolyVec) -> i32 { v.iter().flat_map(|p| p.iter()).map(|x| x.abs()).max().unwrap() }

/// Baseline distinguishers (adversary knows r1, r2):
///   D1 fires  ⇔ ‖z − r1‖∞ ≥ γ1 − β − η
///   D2 fires  ⇔ C_η(A z − c t1 2^d + r2, h) = 0
///   D3 fires  ⇔ ‖LowBits(A z − c t)‖∞ ≥ γ2 − β     (needs t0; informational)
fn distinguishers(k: &Keys, sig: &[u8; SIG_LEN], w: &ad::Witness) -> (bool, bool, bool) {
    let d = ad::decode_sig(sig).unwrap();
    let d1 = exact_norm(&sub(&d.z, &w.r1)) >= ad::GAMMA1 - ad::BETA - ad::ETA;
    let u = ad::u_vec(&k.pk, &d);
    let d2 = !ad::cond_c(&add_mod(&u, &w.r2), &d.h, ad::ETA);
    let ct0 = ad::challenge_mul(&d.c_tilde, k.sk.t0());
    let azct = core::array::from_fn(|i| core::array::from_fn(|n| (u[i][n] - ct0[i][n]).rem_euclid(ad::MODULUS)));
    let d3 = ad::norm_inf(&ad::low_bits_vec(&azct)) >= ad::GAMMA2 - ad::BETA;
    (d1, d2, d3)
}

/// Distinguishers against the filtered scheme (§4.5); all must be silent on both sides.
///   D1′ ⇔ ‖z − r1‖∞ ≥ γ1−β−η ;  D2′ ⇔ C_η(u + r2, h) = 0 ;  D3′ ⇔ ‖LowBits(A z − c t + r2)‖∞ ≥ γ2 − β
fn distinguishers_filtered(k: &Keys, sig: &[u8; SIG_LEN], w: &ad::Witness) -> (bool, bool, bool) {
    let d = ad::decode_sig(sig).unwrap();
    let d1 = exact_norm(&sub(&d.z, &w.r1)) >= ad::GAMMA1 - ad::BETA - ad::ETA;
    let u = ad::u_vec(&k.pk, &d);
    let d2 = !ad::cond_c(&add_mod(&u, &w.r2), &d.h, ad::ETA);
    let ct0 = ad::challenge_mul(&d.c_tilde, k.sk.t0());
    let x = core::array::from_fn(|i| core::array::from_fn(|n| (u[i][n] - ct0[i][n] + w.r2[i][n]).rem_euclid(ad::MODULUS)));
    let d3 = ad::norm_inf(&ad::low_bits_vec(&x)) >= ad::GAMMA2 - ad::BETA;
    (d1, d2, d3)
}

fn pct(k: u64, n: u64) -> String {
    let (p, lo, hi) = wilson(k, n);
    format!("{k}/{n} = {:.3}% [95% CI {:.3}%, {:.3}%]", 100.0 * p, 100.0 * lo, 100.0 * hi)
}
fn mci(xs: &[f64]) -> String {
    let (m, h) = mean_ci(xs);
    format!("{m:.4} ± {h:.4}")
}

fn main() {
    let a = parse();
    let mut rep = String::new();
    macro_rules! out { ($($t:tt)*) => {{ let s = format!($($t)*); println!("{s}"); writeln!(rep, "{s}").unwrap(); }} }
    let t_all = Instant::now();
    out!("# ML-DSA-44 adaptor signature — §5.2 experiments (Rust)");
    out!("");
    out!("seed = {}, N = {}, N_noC = {}, N_filter = {}, N_det = {}, N_time = {}", a.seed, a.n, a.n_noc, a.n_filter, a.n_det, a.n_time);
    out!("");

    // ------------------------------------------------------------------ items 1, 3, 4, 8
    let mut rng = rng_from(a.seed);
    let mut ok_pre = 0u64;
    let mut ok_ver = [0u64; 3];
    let mut ok_ext = 0u64;
    let (mut it_sign, mut it_pre) = (Vec::new(), Vec::new());
    let (mut f1, mut f2, mut f12, mut f3) = (0u64, 0u64, 0u64, 0u64);
    let (mut a1, mut a2, mut a3) = (0u64, 0u64, 0u64);
    let mut max_pre_rounds = 0u32;
    for t in 0..a.n {
        let k = Keys::gen(&mut rng);
        let (y, w) = ad::rgen(&k.pk, &bytes64(&mut rng));
        let msg = random_msg(&mut rng);
        let ctx: &[u8] = if t % 2 == 0 { b"" } else { b"5.2-ctx" };
        // fresh ML-DSA signature (generic loop == fips204 Sign byte-for-byte; see tests)
        let (s, rs) = ad::sign_counting(&k.sk, &msg, ctx, &bytes32(&mut rng)).unwrap();
        it_sign.push(rs as f64);
        let (d1, d2, d3) = distinguishers(&k, &s, &w);
        f1 += d1 as u64; f2 += d2 as u64; f12 += (d1 || d2) as u64; f3 += d3 as u64;
        // PreSign: alternate hedged / deterministic
        let rnd = if t % 4 == 3 { [0u8; 32] } else { bytes32(&mut rng) };
        let (ps, rp) = ad::pre_sign(&k.sk, &msg, ctx, &y, &rnd).expect("iteration cap hit");
        it_pre.push(rp as f64);
        max_pre_rounds = max_pre_rounds.max(rp);
        if !ad::pre_verify(&k.pk, &msg, ctx, &y, &ps) { continue; }
        ok_pre += 1;
        let sig = ad::adapt(&k.pk, &msg, ctx, &y, &ps, &w).unwrap();
        for (j, v) in ALL_VERIFIERS.iter().enumerate() {
            ok_ver[j] += v.verify(&k.pk_bytes, &msg, ctx, &sig) as u64;
        }
        if ad::extract(&k.pk, &ps, &sig, &y).map(|e| e == w).unwrap_or(false) { ok_ext += 1; }
        let (e1, e2, e3) = distinguishers(&k, &sig, &w);
        a1 += e1 as u64; a2 += e2 as u64; a3 += e3 as u64;
    }
    out!("## 1 / 8. Correctness: PreSign → PreVerify → Adapt → unmodified FIPS 204 Verify → Extract");
    out!("PreVerify accepted: {}", pct(ok_pre, a.n));
    for (j, v) in ALL_VERIFIERS.iter().enumerate() {
        out!("adapted signature accepted by {}: {}", v.name(), pct(ok_ver[j], a.n));
    }
    out!("Extract returned exactly (r1, r2): {}", pct(ok_ext, a.n));
    out!("(half the trials with ctx = \"5.2-ctx\", one quarter of PreSigns deterministic; max PreSign rounds seen = {max_pre_rounds}, cap = {})", ad::KAPPA_MAX);
    out!("");
    out!("## 3. Rounds per signature");
    let (ms, _) = mean_ci(&it_sign);
    let (mp, _) = mean_ci(&it_pre);
    out!("ML-DSA Sign rounds: {}", mci(&it_sign));
    out!("PreSign rounds:     {}", mci(&it_pre));
    out!("PreSign / Sign = {:.4}  (extra {:+.2}%)", mp / ms, 100.0 * (mp / ms - 1.0));
    out!("");
    out!("## 4. Unlinkability distinguishers (adversary knows r1, r2)");
    out!("fresh ML-DSA signatures — D1 (‖z − r1‖∞ ≥ γ1−β−η): {}", pct(f1, a.n));
    out!("fresh ML-DSA signatures — D2 (C(Az − c t1 2^d + r2, h) = 0): {}", pct(f2, a.n));
    out!("fresh ML-DSA signatures — D1 ∪ D2: {}", pct(f12, a.n));
    out!("adapted signatures — D1: {a1}, D2: {a2}  (must be 0 of {ok_pre})");
    out!("[info] D3 (needs t0; ‖LowBits(Az − c t)‖∞ ≥ γ2−β): fresh {} | adapted {}", pct(f3, a.n), pct(a3, ok_pre));
    out!("");

    // ------------------------------------------------------------------ item 2
    let mut rng = rng_from(a.seed.wrapping_add(2));
    let (mut noc_total, mut noc_bad) = (0u64, 0u64);
    let mut noc_bad_by = [0u64; 3];
    for _ in 0..a.n_noc {
        let k = Keys::gen(&mut rng);
        let (y, w) = ad::rgen(&k.pk, &bytes64(&mut rng));
        let msg = random_msg(&mut rng);
        let (ps, _) = ad::sign_generic(&k.sk, &msg, b"", Some(&y), &bytes32(&mut rng), SignOpts::PRESIGN_NO_C).unwrap();
        let Ok(sig) = ad::adapt_opt(&k.pk, &msg, b"", &y, &ps, &w, false) else { continue };
        noc_total += 1;
        let res: Vec<bool> = ALL_VERIFIERS.iter().map(|v| v.verify(&k.pk_bytes, &msg, b"", &sig)).collect();
        for j in 0..3 { noc_bad_by[j] += (!res[j]) as u64; }
        if !res[0] { noc_bad += 1; }
    }
    out!("## 2. Necessity of C (C removed from both PreSign and PreVerify)");
    out!("passed PreVerify-without-C but adapted signature rejected by Verify: {}", pct(noc_bad, noc_total));
    out!("(rejections per verifier: fips204 {}, RustCrypto {}, PQClean {} — must agree)", noc_bad_by[0], noc_bad_by[1], noc_bad_by[2]);
    out!("");

    // ------------------------------------------------------------------ item 5 (filtered variant)
    let mut rng = rng_from(a.seed.wrapping_add(5));
    let (mut it_sign_b, mut it_signp) = (Vec::new(), Vec::new());
    let (mut tries, mut rej) = (0u64, 0u64);
    let (mut g1f, mut g2f, mut g3f, mut g1a, mut g2a, mut g3a) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut filt_ver_ok = 0u64;
    for _ in 0..a.n_filter {
        let k = Keys::gen(&mut rng);
        let (y, w) = ad::rgen(&k.pk, &bytes64(&mut rng));
        let msg = random_msg(&mut rng);
        let (_, rb) = ad::sign_counting(&k.sk, &msg, b"", &bytes32(&mut rng)).unwrap();
        it_sign_b.push(rb as f64);
        let (s, rsp) = ad::sign_generic(&k.sk, &msg, b"", None, &bytes32(&mut rng), SignOpts::FILTERED).unwrap();
        it_signp.push(rsp as f64);
        assert!(ad::filter_ok(&k.pk, k.sk.t0(), &s) && verify_fips204(&k.pk_bytes, &msg, b"", &s));
        let (x1, x2, x3) = distinguishers_filtered(&k, &s, &w);
        g1f += x1 as u64; g2f += x2 as u64; g3f += x3 as u64;
        let sa = loop {
            tries += 1;
            let (ps, _) = ad::pre_sign(&k.sk, &msg, b"", &y, &bytes32(&mut rng)).unwrap();
            match ad::filter_adapt(&k.pk, k.sk.t0(), &msg, b"", &y, &ps, &w).unwrap() {
                Some(sa) => break sa,
                None => rej += 1,
            }
        };
        filt_ver_ok += ALL_VERIFIERS.iter().all(|v| v.verify(&k.pk_bytes, &msg, b"", &sa)) as u64;
        let (y1, y2, y3) = distinguishers_filtered(&k, &sa, &w);
        g1a += y1 as u64; g2a += y2 as u64; g3a += y3 as u64;
    }
    let (mb, _) = mean_ci(&it_sign_b);
    let (mf, _) = mean_ci(&it_signp);
    out!("## 5. Filtered variant (§4.5)");
    out!("Sign rounds {} | Sign′ rounds {} | Sign′/Sign = {:.4} (extra {:+.2}%)", mci(&it_sign_b), mci(&it_signp), mf / mb, 100.0 * (mf / mb - 1.0));
    out!("FilterAdapt rejection rate: {}", pct(rej, tries));
    out!("filtered adapted signatures accepted by all three verifiers: {}", pct(filt_ver_ok, a.n_filter));
    out!("distinguishers on fresh Sign′: D1′ {g1f}, D2′ {g2f}, D3′ {g3f} | on FilterAdapt output: D1′ {g1a}, D2′ {g2a}, D3′ {g3a}  (all must be 0 of {})", a.n_filter);
    out!("");

    // ------------------------------------------------------------------ item 6
    let mut rng = rng_from(a.seed.wrapping_add(6));
    let mut min_diff = i32::MAX;
    let mut det_repro = 0u64;
    for _ in 0..a.n_det {
        let k = Keys::gen(&mut rng);
        let msg = random_msg(&mut rng);
        let (y1, _) = ad::rgen(&k.pk, &bytes64(&mut rng));
        let (y2, _) = ad::rgen(&k.pk, &bytes64(&mut rng));
        let (p1, _) = ad::pre_sign(&k.sk, &msg, b"", &y1, &[0u8; 32]).unwrap();
        let (p2, _) = ad::pre_sign(&k.sk, &msg, b"", &y2, &[0u8; 32]).unwrap();
        let (p1b, _) = ad::pre_sign(&k.sk, &msg, b"", &y1, &[0u8; 32]).unwrap();
        det_repro += (p1 == p1b) as u64;
        let z1 = ad::decode_sig(&p1).unwrap().z;
        let z2 = ad::decode_sig(&p2).unwrap().z;
        min_diff = min_diff.min(exact_norm(&sub(&z1, &z2)));
    }
    out!("## 6. Deterministic-mode self-check (same M, two different Y, rnd = 0)");
    out!("min over {} pairs of ‖ẑ − ẑ′‖∞ = {min_diff}  (a leak would make this ≤ 2β = {}); same (M, Y) reproduced bit-exactly: {det_repro}/{}", a.n_det, 2 * ad::BETA, a.n_det);
    out!("");

    // ------------------------------------------------------------------ item 7: timing
    out!("## 7. Timing (median over {} runs each, µs; all from byte-encoded keys, i.e. including key decoding and ExpandA)", a.n_time);
    let mut rng = rng_from(a.seed.wrapping_add(7));
    let mut tm: Vec<(&str, Vec<f64>)> = Vec::new();
    let names = ["KeyGen", "Sign (fips204, unmodified)", "Sign (generic loop, same code as PreSign)", "Verify (fips204, unmodified)",
                 "PreSign", "PreVerify", "Adapt (incl. PreVerify)", "Extract", "RGen", "Verify (RustCrypto)", "Verify (PQClean)"];
    for nm in names { tm.push((nm, Vec::with_capacity(a.n_time))); }
    let us = |t: Instant| t.elapsed().as_secs_f64() * 1e6;
    for _ in 0..(a.n_time + 50) {
        let xi = bytes32(&mut rng);
        let t = Instant::now();
        let (pkk, skk) = ml_dsa_44::KG::keygen_from_seed(&xi);
        let e_kg = us(t);
        let (pkb, skb) = (pkk.into_bytes(), skk.into_bytes());
        let msg = random_msg(&mut rng);
        let rnd = bytes32(&mut rng);
        let rseed = bytes64(&mut rng);

        let t = Instant::now();
        let sk1 = ml_dsa_44::PrivateKey::try_from_bytes(skb).unwrap();
        let mut fixed = rand_chacha::ChaCha20Rng::from_seed_bytes(rnd);
        let s_lib = sk1.try_sign_with_rng(&mut fixed, &msg, b"").unwrap();
        let e_sign_lib = us(t);

        let t = Instant::now();
        let skx = ad::SecretKey::from_bytes(&skb).unwrap();
        let (s_gen, _) = ad::sign_counting(&skx, &msg, b"", &rnd).unwrap();
        let e_sign_gen = us(t);
        std::hint::black_box(&s_gen);

        let t = Instant::now();
        let ok = ml_dsa_44::PublicKey::try_from_bytes(pkb).unwrap().verify(&msg, &s_lib, b"");
        let e_ver = us(t);
        assert!(ok);

        let t = Instant::now();
        let pkx = ad::PublicKey::from_bytes(&pkb).unwrap();
        let (y, w) = ad::rgen(&pkx, &rseed);
        let e_rgen = us(t);

        let t = Instant::now();
        let skx2 = ad::SecretKey::from_bytes(&skb).unwrap();
        let (ps, _) = ad::pre_sign(&skx2, &msg, b"", &y, &rnd).unwrap();
        let e_pre = us(t);

        let t = Instant::now();
        let pkx2 = ad::PublicKey::from_bytes(&pkb).unwrap();
        let okp = ad::pre_verify(&pkx2, &msg, b"", &y, &ps);
        let e_pv = us(t);
        assert!(okp);

        let t = Instant::now();
        let pkx3 = ad::PublicKey::from_bytes(&pkb).unwrap();
        let sig = ad::adapt(&pkx3, &msg, b"", &y, &ps, &w).unwrap();
        let e_ad = us(t);

        let t = Instant::now();
        let pkx4 = ad::PublicKey::from_bytes(&pkb).unwrap();
        let ex = ad::extract(&pkx4, &ps, &sig, &y).unwrap();
        let e_ex = us(t);
        assert_eq!(ex, w);

        let t = Instant::now();
        let o1 = verify_rustcrypto(&pkb, &msg, b"", &sig);
        let e_rc = us(t);
        let t = Instant::now();
        let o2 = verify_pqclean(&pkb, &msg, b"", &sig);
        let e_pq = us(t);
        assert!(o1 && o2);

        let vals = [e_kg, e_sign_lib, e_sign_gen, e_ver, e_pre, e_pv, e_ad, e_ex, e_rgen, e_rc, e_pq];
        for (j, v) in vals.iter().enumerate() { tm[j].1.push(*v); }
    }
    out!("| operation | median µs | mean µs |");
    out!("|---|---:|---:|");
    for (nm, v) in tm.iter_mut() {
        let warm: Vec<f64> = v[50..].to_vec();
        let mean = warm.iter().sum::<f64>() / warm.len() as f64;
        let mut w2 = warm.clone();
        out!("| {nm} | {:.1} | {:.1} |", median(&mut w2), mean);
    }
    out!("");
    out!("total wall time {:.1} s", t_all.elapsed().as_secs_f64());
    if let Some(p) = a.out { std::fs::write(p, rep).unwrap(); }
}

trait FromSeedBytes { fn from_seed_bytes(b: [u8; 32]) -> Self; }
impl FromSeedBytes for rand_chacha::ChaCha20Rng {
    fn from_seed_bytes(b: [u8; 32]) -> Self { <Self as rand_core::SeedableRng>::from_seed(b) }
}
