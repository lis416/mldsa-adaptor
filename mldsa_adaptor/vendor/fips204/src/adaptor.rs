//! Adaptor signatures compatible with *unmodified* ML-DSA-44 verification
//! (paper "Compact Lattice-Based Adaptor Signatures Compatible with ML-DSA Verification", revision 2026-10-25).
//!
//! Fork addition to fips204 0.4.6. Nothing in KeyGen / Sign / Verify of the original crate is
//! touched; this module only *reuses* its internal primitives (ExpandA, ExpandMask, ExpandS,
//! SampleInBall, NTT, Decompose/HighBits/LowBits, MakeHint/UseHint, w1Encode, sig/pk/skEncode).
//!
//! All inputs/outputs are standard FIPS 204 byte encodings (keys, signatures), so keys may come
//! from any FIPS 204 implementation and adapted signatures can be checked by independent verifiers.
//!
//! Representation conventions inside this module
//! * every ring element that is hashed, decomposed or compared modulo q is kept *canonical*, i.e.
//!   coefficients in [0, q);
//! * short vectors (y, z, ẑ, r1, r2, s1, s2, t0) are kept as exact integers (centered);
//! * `‖·‖∞` is always the max absolute value of the centered representative.
#![allow(
    missing_docs,
    unreachable_pub,
    dead_code,
    unused_results,
    clippy::all,
    clippy::pedantic,
    trivial_numeric_casts,
    unused_qualifications,
    single_use_lifetimes,
    elided_lifetimes_in_paths,
    variant_size_differences,
    deprecated
)]

use crate::encodings::{pk_decode, sig_decode, sig_encode, sk_decode, w1_encode};
use crate::hashing::{expand_a, expand_mask, expand_s, h256_xof, sample_in_ball};
use crate::helpers::{mat_vec_mul, mont_reduce, to_mont};
use crate::high_low::{high_bits, low_bits, make_hint, use_hint};
use crate::ntt::{inv_ntt, ntt};
use crate::types::{R, T};
use crate::{D, Q};
use sha3::digest::XofReader;

// ---------------------------------------------------------------------------------------------
// Parameters (ML-DSA-44) and derived constants of the paper
// ---------------------------------------------------------------------------------------------
pub const K: usize = 4;
pub const L: usize = 4;
pub const N: usize = 256;
pub const MODULUS: i32 = Q; // 8380417
pub const ETA: i32 = 2;
pub const TAU: i32 = 39;
pub const BETA: i32 = TAU * ETA; // 78
pub const GAMMA1: i32 = 1 << 17; // 131072
pub const GAMMA2: i32 = (Q - 1) / 88; // 95232
pub const OMEGA: i32 = 80;
pub const LAMBDA_DIV4: usize = 32;
pub const SIG_LEN: usize = 2420;
pub const SK_LEN: usize = 2560;
pub const PK_LEN: usize = 1312;
const W1_LEN: usize = 32 * K * 6; // bitlen((q-1)/(2γ2) - 1) = bitlen(43) = 6
/// encY: k·256 coefficients × 23 bits.
pub const ENC_Y_LEN: usize = K * N * 23 / 8; // 2944
/// Iteration cap of PreSign (counted in *rounds*, not in κ which grows by ℓ per round).
pub const KAPPA_MAX: u32 = 4096;
/// Pre-signature box: ‖ẑ‖∞ < γ1 − β − η = 130992.
pub const PRESIGN_Z_BOUND: i32 = GAMMA1 - BETA - ETA;
/// Extracted witness bounds (relation R′): ‖r1‖∞ < 2(γ1 − β) = 261988, ‖r2‖∞ ≤ 4γ2 + 2 = 380930.
pub const R1_BOUND: i32 = 2 * (GAMMA1 - BETA);
pub const R2_BOUND: i32 = 4 * GAMMA2 + 2;

pub type Poly = [i32; N];
/// k = ℓ = 4 for ML-DSA-44, so one type serves R_q^k and R_q^ℓ.
pub type PolyVec = [Poly; 4];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    CtxTooLong,
    BadKey,
    BadStatement,
    Decode,
    IterationCap,
    PreVerifyFailed,
    BadWitness,
    DigestMismatch,
    NotInRelation,
}

// ---------------------------------------------------------------------------------------------
// Small arithmetic helpers
// ---------------------------------------------------------------------------------------------
#[inline]
fn canon(x: i32) -> i32 { x.rem_euclid(Q) }

/// Centered representative in (−(q−1)/2, (q−1)/2].
#[inline]
pub fn centered(x: i32) -> i32 {
    let r = x.rem_euclid(Q);
    if r > (Q - 1) / 2 { r - Q } else { r }
}

#[inline]
fn wrap(v: &PolyVec) -> [R; 4] { core::array::from_fn(|i| R(v[i])) }
#[inline]
fn unwrap(v: &[R; 4]) -> PolyVec { core::array::from_fn(|i| v[i].0) }

fn map2(a: &PolyVec, b: &PolyVec, f: impl Fn(i32, i32) -> i32) -> PolyVec {
    core::array::from_fn(|i| core::array::from_fn(|n| f(a[i][n], b[i][n])))
}
fn map1(a: &PolyVec, f: impl Fn(i32) -> i32) -> PolyVec {
    core::array::from_fn(|i| core::array::from_fn(|n| f(a[i][n])))
}

/// ‖v‖∞ of the centered representative.
pub fn norm_inf(v: &PolyVec) -> i32 {
    v.iter().flat_map(|p| p.iter()).map(|&x| centered(x).abs()).max().unwrap_or(0)
}

pub fn is_canonical(v: &PolyVec) -> bool { v.iter().flat_map(|p| p.iter()).all(|&x| (0..Q).contains(&x)) }

fn hint_weight(h: &PolyVec) -> i32 { h.iter().flat_map(|p| p.iter()).sum() }

/// NTT of a vector whose coefficients satisfy |x| < q, output reduced to [0, q).
fn ntt_canon<const KL: usize>(v: &[R; KL]) -> [T; KL] {
    let mut out = ntt(v);
    for p in &mut out {
        for x in &mut p.0 {
            *x = canon(*x);
        }
    }
    out
}

/// Montgomery-form NTT image, used for pointwise products: mont_reduce(a_hat · b_mont) = NTT(a·b).
fn prep_mont(v: &PolyVec) -> [T; 4] { to_mont(&ntt_canon(&wrap(v))) }

/// c·v for c given by its (canonical) NTT image and v by `prep_mont`; output canonical.
fn cmul_pre(c_hat: &T, v_mont: &[T; 4]) -> PolyVec {
    let prod: [T; 4] = core::array::from_fn(|i| {
        T(core::array::from_fn(|n| mont_reduce(i64::from(c_hat.0[n]) * i64::from(v_mont[i].0[n]))))
    });
    unwrap(&inv_ntt(&prod)) // inv_ntt output is fully reduced to [0, q)
}

fn ntt_poly(c: &Poly) -> T { ntt_canon(&[R(*c)])[0].clone() }

/// A·v (A in NTT form from ExpandA); |v_i| < q; output canonical.
fn mat_mul(a_hat: &[[T; L]; K], v: &PolyVec) -> PolyVec {
    let v_hat = ntt_canon(&wrap(v));
    unwrap(&inv_ntt(&mat_vec_mul(a_hat, &v_hat)))
}

/// Exposed for tests: c·v in R_q, canonical output (|c_i|, |v_i| < q).
pub fn ring_mul_vec(c: &Poly, v: &PolyVec) -> PolyVec { cmul_pre(&ntt_poly(c), &prep_mont(v)) }

/// Exposed for tests: A·v for A = ExpandA(ρ).
pub fn expand_a_mul(rho: &[u8; 32], v: &PolyVec) -> PolyVec { mat_mul(&expand_a::<false, K, L>(rho), v) }

pub fn low_bits_vec(v: &PolyVec) -> PolyVec { map1(v, |x| low_bits(GAMMA2, canon(x))) }
pub fn high_bits_vec(v: &PolyVec) -> PolyVec { map1(v, |x| high_bits(GAMMA2, canon(x))) }

// ---------------------------------------------------------------------------------------------
// Condition C_b(v, h)
//   (C1) ‖LowBits(v)‖∞ < γ2 − b
//   (C2) for every i with h_i = 1: LowBits(v)_i ∉ (−b, b]
// LowBits is the centered r0 of FIPS 204 Decompose (corner case handled as in FIPS 204).
// C = C_η.
// ---------------------------------------------------------------------------------------------
pub fn cond_c(v: &PolyVec, h: &PolyVec, b: i32) -> bool {
    for i in 0..4 {
        for n in 0..N {
            let lb = low_bits(GAMMA2, canon(v[i][n]));
            if lb.abs() >= GAMMA2 - b {
                return false;
            }
            if h[i][n] == 1 && lb > -b && lb <= b {
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------------------------
/// µ = H(tr ‖ M′, 64) with M′ = 0x00 ‖ |ctx| ‖ ctx ‖ M (FIPS 204, pure ML-DSA).
fn mu_of(tr: &[u8; 64], msg: &[u8], ctx: &[u8]) -> Result<[u8; 64], Error> {
    if ctx.len() > 255 {
        return Err(Error::CtxTooLong);
    }
    let mut x = h256_xof(&[tr, &[0u8], &[ctx.len() as u8], ctx, msg]);
    let mut mu = [0u8; 64];
    x.read(&mut mu);
    Ok(mu)
}

/// c̃ = H(µ ‖ w1Encode(w1), λ/4).
fn challenge(mu: &[u8; 64], w1: &PolyVec) -> [u8; LAMBDA_DIV4] {
    let mut buf = [0u8; W1_LEN];
    w1_encode::<K>(GAMMA2, &wrap(w1), &mut buf);
    let mut x = h256_xof(&[mu, &buf]);
    let mut ct = [0u8; LAMBDA_DIV4];
    x.read(&mut ct);
    ct
}

// ---------------------------------------------------------------------------------------------
// encY: SimpleBitPack-style, 23 bits per coefficient, LSB-first.
//   Coefficient j of polynomial i (0 ≤ i < k, 0 ≤ j < 256) occupies bit positions
//   23·(256·i + j) … 23·(256·i + j) + 22 of the output, where bit position p is bit (p mod 8)
//   (least significant first) of byte ⌊p/8⌋ — the same bit order as FIPS 204 BitsToBytes /
//   IntegerToBits. Each polynomial is exactly 736 bytes. Decoding rejects coefficients ≥ q.
// ---------------------------------------------------------------------------------------------
pub fn encode_y(y: &PolyVec) -> Result<[u8; ENC_Y_LEN], Error> {
    let mut out = [0u8; ENC_Y_LEN];
    let (mut acc, mut nbits, mut pos) = (0u64, 0u32, 0usize);
    for p in y {
        for &c in p {
            if !(0..Q).contains(&c) {
                return Err(Error::BadStatement);
            }
            acc |= (c as u64) << nbits;
            nbits += 23;
            while nbits >= 8 {
                out[pos] = acc as u8;
                acc >>= 8;
                nbits -= 8;
                pos += 1;
            }
        }
    }
    debug_assert!(nbits == 0 && pos == ENC_Y_LEN);
    Ok(out)
}

pub fn decode_y(bytes: &[u8; ENC_Y_LEN]) -> Result<PolyVec, Error> {
    let mut y = [[0i32; N]; 4];
    let (mut acc, mut nbits, mut pos) = (0u64, 0u32, 0usize);
    for p in &mut y {
        for c in p.iter_mut() {
            while nbits < 23 {
                acc |= u64::from(bytes[pos]) << nbits;
                pos += 1;
                nbits += 8;
            }
            let v = (acc & ((1 << 23) - 1)) as i32;
            acc >>= 23;
            nbits -= 23;
            if v >= Q {
                return Err(Error::BadStatement);
            }
            *c = v;
        }
    }
    Ok(y)
}

// ---------------------------------------------------------------------------------------------
// Keys (decoded from standard FIPS 204 encodings; KeyGen itself is the unmodified one)
// ---------------------------------------------------------------------------------------------
pub struct SecretKey {
    rho: [u8; 32],
    cap_k: [u8; 32],
    tr: [u8; 64],
    t0: PolyVec,
    a_hat: [[T; L]; K],
    s1_mont: [T; 4],
    s2_mont: [T; 4],
    t0_mont: [T; 4],
}

impl SecretKey {
    pub fn from_bytes(sk: &[u8; SK_LEN]) -> Result<Self, Error> {
        let (rho, cap_k, tr, s1, s2, t0) = sk_decode::<K, L, SK_LEN>(ETA, sk).map_err(|_| Error::BadKey)?;
        let (s1, s2, t0) = (unwrap(&s1), unwrap(&s2), unwrap(&t0));
        Ok(Self {
            rho: *rho,
            cap_k: *cap_k,
            tr: *tr,
            t0,
            a_hat: expand_a::<false, K, L>(rho),
            s1_mont: prep_mont(&s1),
            s2_mont: prep_mont(&s2),
            t0_mont: prep_mont(&t0),
        })
    }
    /// t0 (centered); needed only by the optional filtered variant (T2).
    pub fn t0(&self) -> &PolyVec { &self.t0 }
}

pub struct PublicKey {
    rho: [u8; 32],
    tr: [u8; 64],
    a_hat: [[T; L]; K],
    t1_2d_mont: [T; 4],
}

impl PublicKey {
    pub fn from_bytes(pk: &[u8; PK_LEN]) -> Result<Self, Error> {
        let (rho, t1) = pk_decode::<K, PK_LEN>(pk).map_err(|_| Error::BadKey)?;
        let t1_2d = map1(&unwrap(&t1), |x| x << D); // t1 ≤ 1023 ⇒ t1·2^13 ≤ q − 1
        let mut tr = [0u8; 64];
        h256_xof(&[pk]).read(&mut tr);
        Ok(Self { rho: *rho, tr, a_hat: expand_a::<false, K, L>(rho), t1_2d_mont: prep_mont(&t1_2d) })
    }
    pub fn rho(&self) -> &[u8; 32] { &self.rho }
    /// A·v with this key's A (A = ExpandA(ρ), the per-key variant of the paper, Remark 1).
    pub fn a_mul(&self, v: &PolyVec) -> PolyVec { mat_mul(&self.a_hat, v) }
}

// ---------------------------------------------------------------------------------------------
// Hard relation: R_η = {(Y, (r1, r2)) : Y = A r1 + r2, ‖r1‖∞, ‖r2‖∞ ≤ η}
// ---------------------------------------------------------------------------------------------
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    /// centered, ‖r1‖∞ ≤ η for RGen output (≤ R1_BOUND for extracted)
    pub r1: PolyVec,
    /// centered
    pub r2: PolyVec,
}

/// Y = A r1 + r2 (canonical).
pub fn statement_of(pk: &PublicKey, w: &Witness) -> PolyVec {
    map2(&pk.a_mul(&w.r1), &w.r2, |a, b| canon(a + b))
}

/// RGen (per-key A): (r1, r2) ← S_η^ℓ × S_η^k via ExpandS(seed) (same sampler as s1, s2).
pub fn rgen(pk: &PublicKey, seed: &[u8; 64]) -> (PolyVec, Witness) {
    let (r1, r2) = expand_s::<false, K, L>(ETA, seed);
    let w = Witness { r1: unwrap(&r1), r2: unwrap(&r2) };
    (statement_of(pk, &w), w)
}

// ---------------------------------------------------------------------------------------------
// Generic signing loop.  One loop serves ML-DSA Sign, PreSign, PreSign without C, and the
// filtered Sign′ of §4.5, exactly like the Python simulator's `sign()`:
//   Y = None  : ρ″ = H(K ‖ rnd ‖ µ)            (FIPS 204, byte-identical for SignOpts::MLDSA)
//   Y = Some  : ρ″ = H(K ‖ rnd ‖ µ ‖ encY)     (change 0, Remark 2)  and  w = A y + Y (change 1)
//   rejection : ‖z‖∞ ≥ γ1 − β − zmarg, ‖r0‖∞ ≥ γ2 − β − r0marg   (change 2: zmarg = η)
//               ‖c t0‖∞ ≥ γ2, wt(h) > ω, and C_{cmarg}(v, h) = 0 if cmarg is set (change 3)
// ---------------------------------------------------------------------------------------------
#[derive(Clone, Copy, Debug)]
pub struct SignOpts {
    pub zmarg: i32,
    pub r0marg: i32,
    pub cmarg: Option<i32>,
}
impl SignOpts {
    pub const MLDSA: Self = Self { zmarg: 0, r0marg: 0, cmarg: None };
    pub const PRESIGN: Self = Self { zmarg: ETA, r0marg: 0, cmarg: Some(ETA) };
    pub const PRESIGN_NO_C: Self = Self { zmarg: ETA, r0marg: 0, cmarg: None };
    /// Sign′ of §4.5: (T1) zmarg = 2η, (T2) r0marg = η, (T3) C_{2η}.
    pub const FILTERED: Self = Self { zmarg: 2 * ETA, r0marg: ETA, cmarg: Some(2 * ETA) };
}

/// Returns (σ, number of rounds).
pub fn sign_generic(
    sk: &SecretKey, msg: &[u8], ctx: &[u8], y_stmt: Option<&PolyVec>, rnd: &[u8; 32], opts: SignOpts,
) -> Result<([u8; SIG_LEN], u32), Error> {
    let mu = mu_of(&sk.tr, msg, ctx)?;
    let mut rho2 = [0u8; 64];
    match y_stmt {
        Some(y) => {
            let enc = encode_y(y)?;
            h256_xof(&[&sk.cap_k, rnd, &mu, &enc]).read(&mut rho2);
        }
        None => h256_xof(&[&sk.cap_k, rnd, &mu]).read(&mut rho2),
    }
    let mut kappa: u16 = 0;
    for round in 1..=KAPPA_MAX {
        let y: PolyVec = unwrap(&expand_mask::<L>(GAMMA1, &rho2, kappa));
        kappa += L as u16;

        let mut w = mat_mul(&sk.a_hat, &y);
        if let Some(ys) = y_stmt {
            w = map2(&w, ys, |a, b| canon(a + b));
        }
        let w1 = high_bits_vec(&w);
        let c_tilde = challenge(&mu, &w1);
        let c_hat = ntt_poly(&sample_in_ball::<false>(TAU, &c_tilde).0);

        let cs1 = cmul_pre(&c_hat, &sk.s1_mont);
        let z = map2(&y, &cs1, |a, b| a + centered(b)); // exact integers
        if z.iter().flat_map(|p| p.iter()).any(|x| x.abs() >= GAMMA1 - BETA - opts.zmarg) {
            continue;
        }
        let cs2 = cmul_pre(&c_hat, &sk.s2_mont);
        let wcs2 = map2(&w, &cs2, |a, b| canon(a - b));
        let r0 = low_bits_vec(&wcs2);
        if r0.iter().flat_map(|p| p.iter()).any(|x| x.abs() >= GAMMA2 - BETA - opts.r0marg) {
            continue;
        }
        let ct0 = cmul_pre(&c_hat, &sk.t0_mont);
        if norm_inf(&ct0) >= GAMMA2 {
            continue;
        }
        let v = map2(&wcs2, &ct0, |a, b| canon(a + b));
        let h: PolyVec = core::array::from_fn(|i| {
            core::array::from_fn(|n| i32::from(make_hint(GAMMA2, canon(-ct0[i][n]), v[i][n])))
        });
        if hint_weight(&h) > OMEGA {
            continue;
        }
        if let Some(b) = opts.cmarg {
            if !cond_c(&v, &h, b) {
                continue;
            }
        }
        let sig = sig_encode::<false, K, L, LAMBDA_DIV4, SIG_LEN>(GAMMA1, OMEGA, &c_tilde, &wrap(&z), &wrap(&h));
        return Ok((sig, round));
    }
    Err(Error::IterationCap)
}

/// ML-DSA.Sign re-expressed through the generic loop (for iteration statistics; byte-identical
/// to the crate's Sign — checked in tests).
pub fn sign_counting(sk: &SecretKey, msg: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Result<([u8; SIG_LEN], u32), Error> {
    sign_generic(sk, msg, ctx, None, rnd, SignOpts::MLDSA)
}

/// PreSign(sk, M, ctx, Y). `rnd` = 32 random bytes (hedged) or all-zero (deterministic).
pub fn pre_sign(sk: &SecretKey, msg: &[u8], ctx: &[u8], y: &PolyVec, rnd: &[u8; 32]) -> Result<([u8; SIG_LEN], u32), Error> {
    sign_generic(sk, msg, ctx, Some(y), rnd, SignOpts::PRESIGN)
}

// ---------------------------------------------------------------------------------------------
// Decoding helper
// ---------------------------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct DecodedSig {
    pub c_tilde: [u8; LAMBDA_DIV4],
    /// exact integers in [−(γ1−1), γ1]
    pub z: PolyVec,
    /// 0/1
    pub h: PolyVec,
}

/// sigDecode; any non-canonical encoding (malformed hint) is rejected.
pub fn decode_sig(sig: &[u8; SIG_LEN]) -> Result<DecodedSig, Error> {
    match sig_decode::<K, L, LAMBDA_DIV4, SIG_LEN>(GAMMA1, OMEGA, sig) {
        Ok((c_tilde, z, Some(h))) => Ok(DecodedSig { c_tilde, z: unwrap(&z), h: unwrap(&h) }),
        _ => Err(Error::Decode),
    }
}

/// u = A z − c·t1·2^d (canonical) — what Verify computes before UseHint.
pub fn u_vec(pk: &PublicKey, d: &DecodedSig) -> PolyVec {
    let c_hat = ntt_poly(&sample_in_ball::<false>(TAU, &d.c_tilde).0);
    let az = pk.a_mul(&d.z);
    let ct1 = cmul_pre(&c_hat, &pk.t1_2d_mont);
    map2(&az, &ct1, |a, b| canon(a - b))
}

/// c·v for the challenge polynomial derived from c̃ (canonical).
pub fn challenge_mul(c_tilde: &[u8; LAMBDA_DIV4], v: &PolyVec) -> PolyVec {
    ring_mul_vec(&sample_in_ball::<false>(TAU, c_tilde).0, v)
}

// ---------------------------------------------------------------------------------------------
// PreVerify(vk, M, ctx, Y, σ̂)
// ---------------------------------------------------------------------------------------------
/// `use_c = false` only for the "necessity of C" experiment.
pub fn pre_verify_opt(pk: &PublicKey, msg: &[u8], ctx: &[u8], y: &PolyVec, presig: &[u8; SIG_LEN], use_c: bool) -> bool {
    let Ok(mu) = mu_of(&pk.tr, msg, ctx) else { return false };
    if !is_canonical(y) {
        return false;
    }
    let Ok(d) = decode_sig(presig) else { return false };
    if d.z.iter().flat_map(|p| p.iter()).any(|x| x.abs() >= PRESIGN_Z_BOUND) {
        return false;
    }
    if hint_weight(&d.h) > OMEGA {
        return false;
    }
    let u = u_vec(pk, &d);
    let v = map2(&u, y, |a, b| canon(a + b)); // v = A ẑ − c t1 2^d + Y
    if use_c && !cond_c(&v, &d.h, ETA) {
        return false;
    }
    let w1p: PolyVec = core::array::from_fn(|i| core::array::from_fn(|n| use_hint(GAMMA2, d.h[i][n], v[i][n])));
    challenge(&mu, &w1p) == d.c_tilde
}

pub fn pre_verify(pk: &PublicKey, msg: &[u8], ctx: &[u8], y: &PolyVec, presig: &[u8; SIG_LEN]) -> bool {
    pre_verify_opt(pk, msg, ctx, y, presig, true)
}

// ---------------------------------------------------------------------------------------------
// Adapt and Extract
// ---------------------------------------------------------------------------------------------
/// Adapt: if PreVerify fails → Err; else σ = sigEncode(c̃, ẑ + r1, h) with h unchanged.
/// (API guard, not in the paper: a witness with ‖r1‖∞ > η is rejected, so that the encoding
/// precondition |z| ≤ γ1 can never be violated by a malformed witness.)
pub fn adapt(pk: &PublicKey, msg: &[u8], ctx: &[u8], y: &PolyVec, presig: &[u8; SIG_LEN], w: &Witness) -> Result<[u8; SIG_LEN], Error> {
    adapt_opt(pk, msg, ctx, y, presig, w, true)
}

pub fn adapt_opt(
    pk: &PublicKey, msg: &[u8], ctx: &[u8], y: &PolyVec, presig: &[u8; SIG_LEN], w: &Witness, use_c: bool,
) -> Result<[u8; SIG_LEN], Error> {
    if !pre_verify_opt(pk, msg, ctx, y, presig, use_c) {
        return Err(Error::PreVerifyFailed);
    }
    if w.r1.iter().flat_map(|p| p.iter()).any(|x| x.abs() > ETA) {
        return Err(Error::BadWitness);
    }
    let d = decode_sig(presig)?;
    let z = map2(&d.z, &w.r1, |a, b| a + b);
    Ok(sig_encode::<false, K, L, LAMBDA_DIV4, SIG_LEN>(GAMMA1, OMEGA, &d.c_tilde, &wrap(&z), &wrap(&d.h)))
}

/// Extract(vk, σ̂, σ, Y): digest check, r1 = z − ẑ, r2 = Y − A r1 (centered), (Y,(r1,r2)) ∈ R′.
pub fn extract(pk: &PublicKey, presig: &[u8; SIG_LEN], sig: &[u8; SIG_LEN], y: &PolyVec) -> Result<Witness, Error> {
    if !is_canonical(y) {
        return Err(Error::BadStatement);
    }
    let dh = decode_sig(presig)?;
    let d = decode_sig(sig)?;
    if d.c_tilde != dh.c_tilde {
        return Err(Error::DigestMismatch);
    }
    let r1 = map2(&d.z, &dh.z, |a, b| a - b); // exact, |r1| < 2γ1 < q/2
    let r2 = map2(y, &pk.a_mul(&r1), |a, b| centered(a - b));
    let n1 = r1.iter().flat_map(|p| p.iter()).map(|x| x.abs()).max().unwrap_or(0);
    let n2 = r2.iter().flat_map(|p| p.iter()).map(|x| x.abs()).max().unwrap_or(0);
    if n1 >= R1_BOUND || n2 > R2_BOUND {
        return Err(Error::NotInRelation);
    }
    Ok(Witness { r1, r2 })
}

// ---------------------------------------------------------------------------------------------
// Optional filtered variant (§4.5)
//   (T1) ‖z‖∞ < γ1 − β − 2η
//   (T2) ‖LowBits(A z − c t)‖∞ < γ2 − β − η    (t = t1·2^d + t0, so needs t0)
//   (T3) C_{2η}(A z − c t1 2^d, h) = 1
// ---------------------------------------------------------------------------------------------
pub fn filter_ok(pk: &PublicKey, t0: &PolyVec, sig: &[u8; SIG_LEN]) -> bool {
    let Ok(d) = decode_sig(sig) else { return false };
    if d.z.iter().flat_map(|p| p.iter()).any(|x| x.abs() >= GAMMA1 - BETA - 2 * ETA) {
        return false;
    }
    let u = u_vec(pk, &d);
    let ct0 = challenge_mul(&d.c_tilde, t0);
    let azct = map2(&u, &ct0, |a, b| canon(a - b));
    if low_bits_vec(&azct).iter().flat_map(|p| p.iter()).any(|x| x.abs() >= GAMMA2 - BETA - ETA) {
        return false;
    }
    cond_c(&u, &d.h, 2 * ETA)
}

/// FilterAdapt = Adapt, then (T1)–(T3); Err(BadWitness) is never produced by the filter itself.
pub fn filter_adapt(
    pk: &PublicKey, t0: &PolyVec, msg: &[u8], ctx: &[u8], y: &PolyVec, presig: &[u8; SIG_LEN], w: &Witness,
) -> Result<Option<[u8; SIG_LEN]>, Error> {
    let s = adapt(pk, msg, ctx, y, presig, w)?;
    Ok(if filter_ok(pk, t0, &s) { Some(s) } else { None })
}
