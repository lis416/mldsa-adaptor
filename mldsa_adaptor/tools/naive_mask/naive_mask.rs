// Remark 2 with the NAIVE derivation rho'' = H(K || rnd || mu): two deterministic pre-signatures on the
// same message under two statements; count pairs whose difference (c - c') s1 is short, and check that
// such a pair recovers s1 (we only test shortness and, as a proxy for recovery, that the difference is
// exactly (c - c') s1 computed from the secret key).
use mldsa_adaptor::ad;
use mldsa_adaptor::*;
fn main() {
    let n = 20000;
    let mut rng = rng_from(20261008);
    let (mut short, mut exact) = (0u64, 0u64);
    for _ in 0..n {
        let k = Keys::gen(&mut rng);
        let msg = random_msg(&mut rng);
        let (y1, _) = ad::rgen(&k.pk, &bytes64(&mut rng));
        let (y2, _) = ad::rgen(&k.pk, &bytes64(&mut rng));
        let (p1, _) = ad::pre_sign(&k.sk, &msg, b"", &y1, &[0u8; 32]).unwrap();
        let (p2, _) = ad::pre_sign(&k.sk, &msg, b"", &y2, &[0u8; 32]).unwrap();
        let (d1, d2) = (ad::decode_sig(&p1).unwrap(), ad::decode_sig(&p2).unwrap());
        let diff: ad::PolyVec = core::array::from_fn(|i| core::array::from_fn(|j| d1.z[i][j] - d2.z[i][j]));
        if ad::norm_inf(&diff) <= 2 * ad::BETA {
            short += 1;
            // s1 from the encoded secret key: compare diff with c1 s1 - c2 s1
            let s1 = s1_of(&k.sk_bytes);
            let a = ad::challenge_mul(&d1.c_tilde, &s1);
            let b = ad::challenge_mul(&d2.c_tilde, &s1);
            let ok = (0..4).all(|i| (0..256).all(|j| ad::centered(a[i][j] - b[i][j]) == diff[i][j]));
            exact += ok as u64;
        }
    }
    let (p, lo, hi) = wilson(short, n);
    println!("naive derivation: {short}/{n} pairs with ||z1-z2|| <= 2beta ({:.2}% [{:.2},{:.2}]); of these, difference == (c-c')s1 exactly: {exact}", 100.0*p, 100.0*lo, 100.0*hi);
}
// s1: bytes 128.. of sk, eta=2 packing: 3 bits per coeff, value = eta - b
fn s1_of(sk: &[u8; SK_LEN]) -> ad::PolyVec {
    core::array::from_fn(|i| {
        let off = 128 + i * 96;
        core::array::from_fn(|j| {
            let bit = j * 3;
            let w = (sk[off + bit / 8] as u32) | ((*sk.get(off + bit / 8 + 1).unwrap_or(&0) as u32) << 8);
            2 - ((w >> (bit % 8)) & 7) as i32
        })
    })
}
