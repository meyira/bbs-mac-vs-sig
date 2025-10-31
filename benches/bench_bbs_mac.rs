use bbs_mac_vs_sig::{BbsProof, BbsPublicKey, BbsSignatureParams};
use bls12_381::{G1Projective, Scalar as Bls12_381Scalar};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use curve25519_dalek::{RistrettoPoint, Scalar as RistrettoScalar};
use ff::Field;

fn bench_verify(c: &mut Criterion) {
    // Setup (not measured)
    let mut rng = rand::thread_rng();
    let num_attributes = 8usize;
    let params_bls = BbsSignatureParams::<G1Projective>::new(num_attributes);
    let params_ristretto = BbsSignatureParams::<RistrettoPoint>::new(num_attributes);
    let x_bls = Bls12_381Scalar::random(&mut rng);
    let x_ristretto = RistrettoScalar::random(&mut rng);

    let mut attributes = Vec::with_capacity(num_attributes);
    for _ in 0..num_attributes {
        attributes.push(Bls12_381Scalar::random(&mut rng));
    }

    let mac_bls = params_bls
        .sign(&x_bls, &attributes, &mut rng)
        .expect("signing should succeed");
    let pk_bls = BbsPublicKey::new(x_bls);

    // Bench: no-pairing verification (MAC verify)
    c.bench_function("verify_mac (no pairing)", |b| {
        b.iter(|| {
            let _ok = params_bls
                .verify(
                    black_box(&x_bls),
                    black_box(&attributes),
                    black_box(&mac_bls),
                )
                .is_ok();
            _ok
        })
    });

    // Bench: pairing-based verification with public key
    c.bench_function("verify_with_pk (pairing)", |b| {
        b.iter(|| {
            let _ok = BbsProof::verify_with_pk(
                black_box(&pk),
                black_box(&attributes),
                black_box(&mac),
                black_box(&params),
            );
            _ok
        })
    });
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
