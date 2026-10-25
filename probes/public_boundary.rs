// Historical probe for the public one-sided test of Section 4.7 (|LowBits(u)_i| = gamma2).
// Written and run by Codex on 2026-10-19 against mldsa_adaptor commit 732e5f8cb0c24fff662905dd363ac0a62b87837c
// (the standalone Rust repository at that time), ML-DSA-44, seed 20261019, 20 000 trials.
// Recorded output:
//   seed=20261019 n=20000 fresh_boundary=106 adapted_boundary=0 rate=0.00530000 wilson95=[0.00438435,0.00640565]
// Saved here 2026-10-25 as-is from the 10/19 review report (review_rev_20261019.md); not re-run and not
// re-compiled on 2026-10-25. Helpers (rng_from, bytes32, bytes64, random_msg, wilson) are those of the
// crate's test/tool code at that commit. To publish: move to src/bin/public_boundary.rs and record the
// build/run command, version and stdout of a fresh run.
use mldsa_adaptor::{ad,Keys,rng_from,bytes32,bytes64,random_msg,wilson};
fn boundary(pk:&ad::PublicKey,sig:&[u8;ad::SIG_LEN])->bool{
 let d=ad::decode_sig(sig).unwrap();
 ad::low_bits_vec(&ad::u_vec(pk,&d)).iter().flatten().any(|x|x.abs()==ad::GAMMA2)
}
fn main(){
 let n=20000u64;let mut rng=rng_from(20261019);let(mut fresh,mut adapted)=(0u64,0u64);
 for _ in 0..n {
  let k=Keys::gen(&mut rng);let msg=random_msg(&mut rng);let rnd=bytes32(&mut rng);
  let (sig,_)=ad::sign_counting(&k.sk,&msg,b"",&rnd).unwrap();
  if boundary(&k.pk,&sig){fresh+=1;}
  let (r,w)=ad::rgen(&k.pk,&bytes64(&mut rng));
  let (pre,_)=ad::pre_sign(&k.sk,&msg,b"",&r,&bytes32(&mut rng)).unwrap();
  let sig=ad::adapt(&k.pk,&msg,b"",&r,&pre,&w).unwrap();
  if boundary(&k.pk,&sig){adapted+=1;}
 }
 let(p,lo,hi)=wilson(fresh,n);
 println!("seed=20261019 n={} fresh_boundary={} adapted_boundary={} rate={:.8} wilson95=[{:.8},{:.8}]",n,fresh,adapted,p,lo,hi);
}
