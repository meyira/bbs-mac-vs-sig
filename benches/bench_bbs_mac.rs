use bbs_mac_vs_sig::{BbsPublicKey, BbsSignatureParams};
use bls12_381::{G1Projective, Scalar as Bls12_381Scalar};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use curve25519_dalek::{RistrettoPoint, Scalar as RistrettoScalar};
use ff::Field;

/// Benchmarks verification routines for a single attribute count.
///
/// For the given `num_attributes`, this:
/// - Builds parameters for both curves (Ristretto and BLS12-381 G1).
/// - Samples random attributes and a secret key per curve.
/// - Signs, then measures three variants:
///   - Ristretto MAC verify (no pairing)
///   - BLS12-381 MAC verify (no pairing)
///   - Pairing-based verification with a public key (BLS12-381)
///
/// Each Criterion benchmark name is suffixed with `(n=...)` so results for
/// different sizes are distinguishable.
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

    let group_name = format!("verify n={}", num_attributes);
    let mut group = c.benchmark_group(group_name);

    #[cfg(feature = "ristretto")]
    {
        group.bench_function("ristretto_mac", |b| {
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
    }

    #[cfg(feature = "bls")]
    {
        group.bench_function("bls_mac", |b| {
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
    }

    #[cfg(feature = "pairing")]
    {
        group.bench_function("bls_pairing", |b| {
            b.iter(|| {
                let _ok = params_bls.verify_with_pk(
                    black_box(&pk_bls),
                    black_box(&attributes_bls),
                    black_box(&mac_bls),
                );
                _ok
            })
        });
    }

    group.finish();
}

/// Runs the verification benchmarks across multiple attribute counts.
///
/// Currently benchmarks: 5, 10, 15, 25, and 50 attributes. Modify the list
/// to add or remove sizes as needed.
fn bench_all(c: &mut Criterion) {
    for n in [5usize, 10, 15, 25, 50] {
        bench_for_size(c, n);
    }
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
