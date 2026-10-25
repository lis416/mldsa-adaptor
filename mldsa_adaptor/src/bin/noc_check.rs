// Re-runs item 2 with the exact seed of expt and checks that every pre-signature whose adapted
// signature fails Verify is rejected by PreVerify *with* C.
use mldsa_adaptor::ad::{self, SignOpts};
use mldsa_adaptor::*;
fn main() {
    let seed: u64 = std::env::args().nth(1).unwrap().parse().unwrap();
    let n: u64 = std::env::args().nth(2).unwrap().parse().unwrap();
    let mut rng = rng_from(seed.wrapping_add(2));
    let (mut total, mut bad, mut bad_rejected_by_c, mut good_rejected_by_c) = (0u64, 0u64, 0u64, 0u64);
    for _ in 0..n {
        let k = Keys::gen(&mut rng);
        let (y, w) = ad::rgen(&k.pk, &bytes64(&mut rng));
        let msg = random_msg(&mut rng);
        let (ps, _) = ad::sign_generic(&k.sk, &msg, b"", Some(&y), &bytes32(&mut rng), SignOpts::PRESIGN_NO_C).unwrap();
        let Ok(sig) = ad::adapt_opt(&k.pk, &msg, b"", &y, &ps, &w, false) else { continue };
        total += 1;
        let with_c = ad::pre_verify(&k.pk, &msg, b"", &y, &ps);
        if !verify_fips204(&k.pk_bytes, &msg, b"", &sig) { bad += 1; bad_rejected_by_c += (!with_c) as u64; }
        else { good_rejected_by_c += (!with_c) as u64; }
    }
    println!("seed {seed}: {bad}/{total} fail after adaptation; of these rejected by PreVerify with C: {bad_rejected_by_c}; (valid ones also rejected by C: {good_rejected_by_c})");
}
