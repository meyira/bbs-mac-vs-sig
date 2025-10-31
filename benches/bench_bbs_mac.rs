use bbs_mac_vs_sig::{BbsProof, BbsPublicKey, BbsSignatureParams};
use bls12_381::{G1Projective, Scalar as Bls12_381Scalar};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use curve25519_dalek::{RistrettoPoint, Scalar as RistrettoScalar};
use ff::Field;

fn bench_for_size(c: &mut Criterion, num_attributes: usize) {
    // Setup (not measured)
    let mut rng = rand::thread_rng();
    let params_bls = BbsSignatureParams::<G1Projective>::new(num_attributes);
    let params_ristretto = BbsSignatureParams::<RistrettoPoint>::new(num_attributes);
    let x_bls = Bls12_381Scalar::random(&mut rng);
    let x_ristretto = RistrettoScalar::random(&mut rng);

    let mut attributes_bls = Vec::with_capacity(num_attributes);
    let mut ristretto_attributes = Vec::with_capacity(num_attributes);
    for _ in 0..num_attributes {
        attributes_bls.push(Bls12_381Scalar::random(&mut rng));
        ristretto_attributes.push(RistrettoScalar::random(&mut rng));
    }

    let mac_bls = params_bls
        .sign(&x_bls, &attributes_bls, &mut rng)
        .expect("signing should succeed");

    let mac_ristretto = params_ristretto
        .sign(&x_ristretto, &ristretto_attributes, &mut rng)
        .expect("signing should succeed");
    let pk_bls = BbsPublicKey::new(x_bls);

    let name_ristretto = format!("verify_mac with ristretto (n={})", num_attributes);
    c.bench_function(name_ristretto.as_str(), |b| {
        b.iter(|| {
            let _ok = params_ristretto
                .verify(
                    black_box(&x_ristretto),
                    black_box(&ristretto_attributes),
                    black_box(&mac_ristretto),
                )
                .is_ok();
            _ok
        })
    });

    let name_bls = format!("verify_mac with bls12 (no pairing) (n={})", num_attributes);
    c.bench_function(name_bls.as_str(), |b| {
        b.iter(|| {
            let _ok = params_bls
                .verify(
                    black_box(&x_bls),
                    black_box(&attributes_bls),
                    black_box(&mac_bls),
                )
                .is_ok();
            _ok
        })
    });

    let name_pairing = format!("verify_with_pk (pairing) (n={})", num_attributes);
    c.bench_function(name_pairing.as_str(), |b| {
        b.iter(|| {
            let _ok = BbsProof::verify_with_pk(
                black_box(&pk_bls),
                black_box(&attributes_bls),
                black_box(&mac_bls),
                black_box(&params_bls),
            );
            _ok
        })
    });
}

fn bench_all(c: &mut Criterion) {
    for n in [5usize, 10, 15, 25, 50] {
        bench_for_size(c, n);
    }
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
