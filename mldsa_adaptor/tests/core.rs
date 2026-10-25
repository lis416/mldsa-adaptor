//! Correctness tests of the adaptor implementation against the paper's spec (RUST_HANDOFF.md).
#![allow(deprecated)]
use mldsa_adaptor::ad::{self, PolyVec, SignOpts};
use mldsa_adaptor::*;
use rand_core::RngCore;

/// Schoolbook negacyclic multiplication in Z_q[X]/(X^256+1), canonical output.
fn schoolbook(a: &[i32; 256], b: &[i32; 256]) -> [i32; 256] {
    let q = ad::MODULUS as i64;
    let mut acc = [0i64; 256];
    for i in 0..256 {
        for j in 0..256 {
            let p = a[i] as i64 * b[j] as i64 % q;
            if i + j < 256 { acc[i + j] += p } else { acc[i + j - 256] -= p }
        }
    }
    core::array::from_fn(|i| acc[i].rem_euclid(q) as i32)
}

fn rand_poly(rng: &mut rand_chacha::ChaCha20Rng, bound: i32) -> [i32; 256] {
    core::array::from_fn(|_| (rng.next_u32() % (2 * bound as u32 + 1)) as i32 - bound)
}

#[test]
fn ring_mul_matches_schoolbook() {
    let mut rng = rng_from(1);
    for bound in [1, 2, 4096, 131072, (ad::MODULUS - 1) / 2] {
        let c = rand_poly(&mut rng, bound);
        let v: PolyVec = core::array::from_fn(|_| rand_poly(&mut rng, bound));
        let got = ad::ring_mul_vec(&c, &v);
        for i in 0..4 {
            assert_eq!(got[i], schoolbook(&c, &v[i]), "bound {bound} row {i}");
        }
    }
}

#[test]
fn encode_y_roundtrip_and_rejects_non_residue() {
    let mut rng = rng_from(2);
    let y: PolyVec = core::array::from_fn(|_| core::array::from_fn(|_| (rng.next_u32() % ad::MODULUS as u32) as i32));
    let enc = ad::encode_y(&y).unwrap();
    assert_eq!(ad::decode_y(&enc).unwrap(), y);
    // bit order: coefficient 0 of poly 0 sits in the low 23 bits of bytes 0..2 (LSB first)
    let c0 = enc[0] as u32 | (enc[1] as u32) << 8 | ((enc[2] as u32) & 0x7f) << 16;
    assert_eq!(c0 as i32, y[0][0]);
    let mut bad = enc;
    // set coefficient 0 to 2^23 - 1 ≥ q
    bad[0] = 0xff;
    bad[1] = 0xff;
    bad[2] |= 0x7f;
    assert_eq!(ad::decode_y(&bad), Err(ad::Error::BadStatement));
    let mut ynon = y;
    ynon[3][255] = ad::MODULUS;
    assert!(ad::encode_y(&ynon).is_err());
}

#[test]
fn generic_loop_is_byte_identical_to_fips204_sign() {
    // SignOpts::MLDSA with Y = None must reproduce the crate's (unmodified) Sign exactly.
    let mut rng = rng_from(3);
    for t in 0..200 {
        let keys = Keys::gen(&mut rng);
        let msg = random_msg(&mut rng);
        let ctx: Vec<u8> = (0..(t % 7) as u8).collect();
        let rnd = if t % 2 == 0 { [0u8; 32] } else { bytes32(&mut rng) };
        let (mine, _) = ad::sign_counting(&keys.sk, &msg, &ctx, &rnd).unwrap();
        let skc = fips204::ml_dsa_44::PrivateKey::try_from_bytes(keys.sk_bytes).unwrap();
        let mut mprime = vec![0u8, ctx.len() as u8];
        mprime.extend_from_slice(&ctx);
        mprime.extend_from_slice(&msg);
        let theirs = fips204::ml_dsa_44::_internal_sign(&skc, &mprime, &[], rnd).unwrap();
        assert_eq!(mine[..], theirs[..], "trial {t}");
        for v in ALL_VERIFIERS {
            assert!(v.verify(&keys.pk_bytes, &msg, &ctx, &mine), "{} trial {t}", v.name());
        }
    }
}
use fips204::traits::SerDes;

#[test]
fn full_protocol_three_verifiers() {
    let mut rng = rng_from(4);
    for t in 0..300 {
        let keys = Keys::gen(&mut rng);
        let (y, w) = ad::rgen(&keys.pk, &bytes64(&mut rng));
        assert!(ad::is_canonical(&y));
        assert!(ad::norm_inf(&w.r1) <= ad::ETA && ad::norm_inf(&w.r2) <= ad::ETA);
        let msg = random_msg(&mut rng);
        let ctx: &[u8] = if t % 3 == 0 { b"" } else { b"adaptor-ctx" };
        let rnd = if t % 2 == 0 { [0u8; 32] } else { bytes32(&mut rng) };
        let (ps, _) = ad::pre_sign(&keys.sk, &msg, ctx, &y, &rnd).unwrap();
        assert!(ad::pre_verify(&keys.pk, &msg, ctx, &y, &ps));
        // a pre-signature is not a signature (it should, overwhelmingly, fail plain Verify)
        // and must fail PreVerify under a different statement / message
        let (y2, _) = ad::rgen(&keys.pk, &bytes64(&mut rng));
        assert!(!ad::pre_verify(&keys.pk, &msg, ctx, &y2, &ps));
        assert!(!ad::pre_verify(&keys.pk, b"other", ctx, &y, &ps));
        let sig = ad::adapt(&keys.pk, &msg, ctx, &y, &ps, &w).unwrap();
        for v in ALL_VERIFIERS {
            assert!(v.verify(&keys.pk_bytes, &msg, ctx, &sig), "{} trial {t}", v.name());
        }
        let ex = ad::extract(&keys.pk, &ps, &sig, &y).unwrap();
        assert_eq!(ex, w, "trial {t}");
    }
}

#[test]
fn extract_rejects_digest_mismatch_and_garbage() {
    let mut rng = rng_from(5);
    let keys = Keys::gen(&mut rng);
    let (y, w) = ad::rgen(&keys.pk, &bytes64(&mut rng));
    let msg = random_msg(&mut rng);
    let (ps, _) = ad::pre_sign(&keys.sk, &msg, b"", &y, &bytes32(&mut rng)).unwrap();
    let sig = ad::adapt(&keys.pk, &msg, b"", &y, &ps, &w).unwrap();
    // an unrelated valid signature on the same message: different c̃ → digest check fires
    let (other, _) = ad::sign_counting(&keys.sk, &msg, b"", &bytes32(&mut rng)).unwrap();
    assert_eq!(ad::extract(&keys.pk, &ps, &other, &y), Err(ad::Error::DigestMismatch));
    // malformed hint section: non-increasing indices → decode error
    let mut bad = sig;
    let hint_start = 32 + 4 * 576;
    bad[hint_start] = 5;
    bad[hint_start + 1] = 3;
    bad[ad::SIG_LEN - 4] = bad[ad::SIG_LEN - 4].max(2);
    assert!(ad::decode_sig(&bad).is_err() || ad::extract(&keys.pk, &ps, &bad, &y).is_err());
    // non-canonical statement
    let mut ybad = y;
    ybad[0][0] = ad::MODULUS;
    assert_eq!(ad::extract(&keys.pk, &ps, &sig, &ybad), Err(ad::Error::BadStatement));
}

#[test]
fn adapt_refuses_bad_presignature() {
    let mut rng = rng_from(6);
    let keys = Keys::gen(&mut rng);
    let (y, w) = ad::rgen(&keys.pk, &bytes64(&mut rng));
    let msg = random_msg(&mut rng);
    let (mut ps, _) = ad::pre_sign(&keys.sk, &msg, b"", &y, &bytes32(&mut rng)).unwrap();
    ps[0] ^= 1;
    assert_eq!(ad::adapt(&keys.pk, &msg, b"", &y, &ps, &w), Err(ad::Error::PreVerifyFailed));
}

#[test]
fn deterministic_mode_mask_depends_on_y() {
    // Item 6: same M, two different Y, rnd = 0: ẑ − ẑ′ must NOT be short.
    let mut rng = rng_from(7);
    for _ in 0..50 {
        let keys = Keys::gen(&mut rng);
        let msg = random_msg(&mut rng);
        let (y1, _) = ad::rgen(&keys.pk, &bytes64(&mut rng));
        let (y2, _) = ad::rgen(&keys.pk, &bytes64(&mut rng));
        let (a, _) = ad::pre_sign(&keys.sk, &msg, b"", &y1, &[0u8; 32]).unwrap();
        let (b, _) = ad::pre_sign(&keys.sk, &msg, b"", &y2, &[0u8; 32]).unwrap();
        let (za, zb) = (ad::decode_sig(&a).unwrap().z, ad::decode_sig(&b).unwrap().z);
        let diff: PolyVec = core::array::from_fn(|i| core::array::from_fn(|n| za[i][n] - zb[i][n]));
        assert!(ad::norm_inf(&diff) > 1000, "ẑ − ẑ′ is short: mask not bound to Y");
        // and determinism itself: same (M, Y) twice gives identical bytes
        let (a2, _) = ad::pre_sign(&keys.sk, &msg, b"", &y1, &[0u8; 32]).unwrap();
        assert_eq!(a[..], a2[..]);
    }
}

#[test]
fn opts_presign_box_and_condition_hold() {
    let mut rng = rng_from(8);
    for _ in 0..200 {
        let keys = Keys::gen(&mut rng);
        let (y, _) = ad::rgen(&keys.pk, &bytes64(&mut rng));
        let msg = random_msg(&mut rng);
        let (ps, _) = ad::sign_generic(&keys.sk, &msg, b"", Some(&y), &bytes32(&mut rng), SignOpts::PRESIGN).unwrap();
        let d = ad::decode_sig(&ps).unwrap();
        assert!(ad::norm_inf(&d.z) < ad::PRESIGN_Z_BOUND);
        let u = ad::u_vec(&keys.pk, &d);
        let v: PolyVec = core::array::from_fn(|i| core::array::from_fn(|n| (u[i][n] + y[i][n]) % ad::MODULUS));
        assert!(ad::cond_c(&v, &d.h, ad::ETA));
    }
}
