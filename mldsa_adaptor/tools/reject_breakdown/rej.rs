use mldsa_adaptor::ad::{self, SignOpts};
use mldsa_adaptor::*;
use std::sync::atomic::Ordering::Relaxed;
fn main() {
    let mut rng = rng_from(424242);
    for (name, opts) in [("Sign", SignOpts::MLDSA), ("PreSign", SignOpts::PRESIGN)] {
        for c in ad::REJ.iter() { c.store(0, Relaxed); }
        for _ in 0..20000 {
            let k = Keys::gen(&mut rng);
            let (y, _) = ad::rgen(&k.pk, &bytes64(&mut rng));
            let msg = random_msg(&mut rng);
            let ys = if name == "Sign" { None } else { Some(&y) };
            ad::sign_generic(&k.sk, &msg, b"", ys, &bytes32(&mut rng), opts).unwrap();
        }
        let r: Vec<u64> = ad::REJ.iter().map(|c| c.load(Relaxed)).collect();
        let rounds: u64 = r.iter().sum();
        let after_z = rounds - r[0]; let after_r0 = after_z - r[1]; let after_ct0 = after_r0 - r[2]; let after_h = after_ct0 - r[3];
        println!("{name}: rounds/sig {:.4} | pass z {:.4} | pass r0|z {:.4} | pass ct0 {:.6} | pass wt(h)≤ω {:.4} | pass C {:.4}",
            rounds as f64 / 20000.0, after_z as f64 / rounds as f64, after_r0 as f64 / after_z as f64,
            after_ct0 as f64 / after_r0 as f64, after_h as f64 / after_ct0 as f64, r[5] as f64 / after_h as f64);
    }
}
