//! Glue for the experiments: key generation, three independent FIPS 204 verifiers, statistics.
pub use fips204::adaptor as ad;
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Verifier};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

pub const PK_LEN: usize = ad::PK_LEN;
pub const SK_LEN: usize = ad::SK_LEN;
pub const SIG_LEN: usize = ad::SIG_LEN;

/// Unmodified FIPS 204 KeyGen (fips204 crate) from a 32-byte seed ξ.
pub fn keygen_from_seed(xi: &[u8; 32]) -> ([u8; PK_LEN], [u8; SK_LEN]) {
    let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(xi);
    (pk.into_bytes(), sk.into_bytes())
}

pub struct Keys {
    pub pk_bytes: [u8; PK_LEN],
    pub sk_bytes: [u8; SK_LEN],
    pub pk: ad::PublicKey,
    pub sk: ad::SecretKey,
}
impl Keys {
    pub fn gen(rng: &mut ChaCha20Rng) -> Self {
        let mut xi = [0u8; 32];
        rng.fill_bytes(&mut xi);
        let (pk_bytes, sk_bytes) = keygen_from_seed(&xi);
        Keys {
            pk: ad::PublicKey::from_bytes(&pk_bytes).expect("pk"),
            sk: ad::SecretKey::from_bytes(&sk_bytes).expect("sk"),
            pk_bytes,
            sk_bytes,
        }
    }
}

// ----------------------------------------------------------------- verifiers (all unmodified)
/// fips204 0.4.6 ML-DSA.Verify (same crate as the primary implementation, but its untouched path).
pub fn verify_fips204(pk: &[u8; PK_LEN], msg: &[u8], ctx: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    match ml_dsa_44::PublicKey::try_from_bytes(*pk) {
        Ok(p) => p.verify(msg, sig, ctx),
        Err(_) => false,
    }
}

/// RustCrypto ml-dsa 0.1.1 — independent pure-Rust implementation.
pub fn verify_rustcrypto(pk: &[u8; PK_LEN], msg: &[u8], ctx: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature, VerifyingKey};
    let Ok(epk) = EncodedVerifyingKey::<MlDsa44>::try_from(&pk[..]) else { return false };
    let Ok(esig) = EncodedSignature::<MlDsa44>::try_from(&sig[..]) else { return false };
    let Some(s) = Signature::<MlDsa44>::decode(&esig) else { return false };
    VerifyingKey::<MlDsa44>::decode(&epk).verify_with_context(msg, ctx, &s)
}

/// PQClean ML-DSA-44 (C, via pqcrypto-mldsa) — independent C implementation.
pub fn verify_pqclean(pk: &[u8; PK_LEN], msg: &[u8], ctx: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    use pqcrypto_mldsa::mldsa44;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
    let Ok(p) = mldsa44::PublicKey::from_bytes(pk) else { return false };
    let Ok(s) = mldsa44::DetachedSignature::from_bytes(sig) else { return false };
    mldsa44::verify_detached_signature_ctx(&s, msg, ctx, &p).is_ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verifier3 {
    Fips204,
    RustCrypto,
    PqClean,
}
pub const ALL_VERIFIERS: [Verifier3; 3] = [Verifier3::Fips204, Verifier3::RustCrypto, Verifier3::PqClean];
impl Verifier3 {
    pub fn name(self) -> &'static str {
        match self {
            Verifier3::Fips204 => "fips204-0.4.6 (unmodified Verify)",
            Verifier3::RustCrypto => "RustCrypto ml-dsa 0.1.1",
            Verifier3::PqClean => "PQClean via pqcrypto-mldsa 0.1.2",
        }
    }
    pub fn verify(self, pk: &[u8; PK_LEN], msg: &[u8], ctx: &[u8], sig: &[u8; SIG_LEN]) -> bool {
        match self {
            Verifier3::Fips204 => verify_fips204(pk, msg, ctx, sig),
            Verifier3::RustCrypto => verify_rustcrypto(pk, msg, ctx, sig),
            Verifier3::PqClean => verify_pqclean(pk, msg, ctx, sig),
        }
    }
}

// ----------------------------------------------------------------- randomness helpers
pub fn rng_from(seed: u64) -> ChaCha20Rng { ChaCha20Rng::seed_from_u64(seed) }
pub fn bytes32(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}
pub fn bytes64(rng: &mut ChaCha20Rng) -> [u8; 64] {
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    b
}
pub fn random_msg(rng: &mut ChaCha20Rng) -> Vec<u8> {
    let mut m = vec![0u8; 32];
    rng.fill_bytes(&mut m);
    m
}

// ----------------------------------------------------------------- statistics
/// Wilson score interval (95%) for k successes in n trials; returns (p, lo, hi).
pub fn wilson(k: u64, n: u64) -> (f64, f64, f64) {
    if n == 0 {
        return (f64::NAN, f64::NAN, f64::NAN);
    }
    let z = 1.959_963_984_540_054_f64;
    let (kf, nf) = (k as f64, n as f64);
    let p = kf / nf;
    let den = 1.0 + z * z / nf;
    let centre = (p + z * z / (2.0 * nf)) / den;
    let half = z * ((p * (1.0 - p) / nf + z * z / (4.0 * nf * nf)).sqrt()) / den;
    (p, (centre - half).max(0.0), (centre + half).min(1.0))
}

/// Mean and 95% normal-approximation half-width.
pub fn mean_ci(xs: &[f64]) -> (f64, f64) {
    let n = xs.len() as f64;
    let m = xs.iter().sum::<f64>() / n;
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (n - 1.0);
    (m, 1.959_963_984_540_054 * (var / n).sqrt())
}

pub fn median(xs: &mut [f64]) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = xs.len();
    if n % 2 == 1 { xs[n / 2] } else { 0.5 * (xs[n / 2 - 1] + xs[n / 2]) }
}
