// Public boundary test, Section 4.7. Preserve seed, sample count and RNG order
// of the historical 2026-10-19 probe; see ../../results/public_boundary_PROVENANCE.md.
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

