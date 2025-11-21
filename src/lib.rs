//! Minimal BBS MAC over BLS12-381: parameters, signing, verification, and tests.
//!
//! This module provides a small, documented implementation suitable for examples
//! and experimentation. It is not audited; do not use in production.

use bls12_381::G1Projective;
use bls12_381::G2Projective;
use bls12_381::Scalar as Bls12_381Scalar;
use bls12_381::pairing;
use ff::Field; // For .invert() and .is_zero()
use group::Curve; // For G1Projective ops (+, *, .generator())
use group::Group; // For G1Projective ops (+, *, .generator())
use rand::RngCore;

/// A BBS Signature struct. Without pairings, it is only privately verifiable, i.e.
/// it needs a private key for verification.
///  The signature has the following components:
/// - `a`: The signature value `A = (x + e)^-1 * (G + m1*H1 + ... + ml*Hl)` for `l` attributes.
/// - `e`: The random scalar used for the signature.
#[derive(Debug)]
pub struct BbsSignature<G: Group> {
    a: G,
    e: G::Scalar,
}

#[derive(Debug)]
pub enum BbsSignatureError {
    /// Thrown when the number of attributes does not match the number of generators.
    InputLengthMismatch,
    /// Thrown when the verification fails (e.g. when the given
    /// `A` != `(x + e)^-1 * (G + m1*H1 + ... + ml*Hl)`).
    VerificationFailed,
}

/// System parameters that define the cryptographic setup for the BBS scheme.
///
/// The generators are going to be used throughout the protocol. The number of
/// generators depends on the number of attributes the BBS scheme is supposed to sign.
#[derive(Clone, Debug)]
pub struct BbsSignatureParams<G: Group> {
    h_generators: Vec<G>,
    g_generator: G,
}

impl<G: Group> BbsSignatureParams<G> {
    /// Generates deterministic parameters for the BBS scheme based on the desired
    /// number of attributes to sign.
    ///
    /// # Arguments
    /// - `num_attributes`: The number of attributes to be signed.
    /// - `rng`: A random number generator.
    ///
    /// # Returns
    /// - `BbsSignatureParams`: the system parameters
    ///
    /// # Example
    /// ```rust
    /// use bbs_mac_vs_sig::BbsSignatureParams;
    /// use curve25519_dalek::RistrettoPoint;
    /// let mut rng = rand::thread_rng();
    ///
    /// let num_attributes = 5;
    /// let params = BbsSignatureParams::<RistrettoPoint>::new(num_attributes);
    /// ```
    pub fn new(num_attributes: usize) -> Self {
        let g_generator = G::generator();
        let mut h_generators = Vec::with_capacity(num_attributes);
        let mut ctr = G::Scalar::ONE;
        for _ in 0..num_attributes {
            h_generators.push(g_generator * ctr);
            ctr += G::Scalar::ONE;
        }
        Self {
            h_generators,
            g_generator,
        }
    }

    /// Implements the core BBS signing computation:
    /// A = (x + e)^-1 * (G + m1*H1 + ... + ml*Hl)
    ///
    /// # Arguments
    /// - `bbs_params`: the system parameters
    /// - `x`: the secret key scalar
    /// - `attributes`: the attributes to be signed
    /// - `rng`: a random number generator
    ///
    /// # Returns
    /// - `Ok(BbsSignature)`: the computed BBS MAC
    /// - `Err(BbsSignatureError::InputLengthMismatch)`: an error if the number of attributes
    ///   does not match the number of generators
    ///
    /// # Example
    /// ```rust
    /// use bbs_mac_vs_sig::{BbsSignatureParams, BbsSignature};
    /// use bls12_381::Scalar as Bls12_381Scalar;
    /// use bls12_381::G1Projective;
    /// use ff::Field;
    ///
    /// let mut rng = rand::thread_rng();
    /// let num_attributes = 5;
    /// let params = BbsSignatureParams::<G1Projective>::new(num_attributes);
    /// let x = Bls12_381Scalar::random(&mut rng);
    /// let attributes: Vec<Bls12_381Scalar> =
    ///     std::iter::repeat_with(|| Bls12_381Scalar::random(&mut rng))
    ///         .take(num_attributes)
    ///         .collect();
    /// let mac: BbsSignature<G1Projective> = params.sign(&x, &attributes, &mut rng).unwrap();
    /// ```
    pub fn sign(
        &self,
        x: &G::Scalar,
        attributes: &[G::Scalar],
        rng: &mut impl RngCore,
    ) -> Result<BbsSignature<G>, BbsSignatureError> {
        if attributes.len() != self.h_generators.len() {
            return Err(BbsSignatureError::InputLengthMismatch);
        }

        // generate random e for the MAC
        let mut e: G::Scalar = G::Scalar::random(&mut *rng);

        // We loop, re-sampling 'e' until (x + e) is non-zero and we get an inverse.
        let d_inv: G::Scalar = loop {
            // Compute the scalar inverse: (x + e)^-1.
            let d: G::Scalar = *x + e; // d = x + e
            match Option::<G::Scalar>::from(d.invert()) {
                Some(inv) => break inv,
                None => {
                    // (x + e) was zero. Sample a new 'e' and the loop will retry.
                    e = G::Scalar::random(&mut *rng);
                }
            }
        };

        // Compute the multi-scalar multiplication with the generators and attributes:
        // `B = G + m1*H1 + ... + ml*Hl`
        // TODO do we have some form of multi-exp here?
        let b: G = self.g_generator
            + attributes
                .iter()
                .zip(self.h_generators.iter())
                .map(|(m, h)| (*h) * (*m))
                .sum::<G>();

        // Compute the final signature component `A = d_inv * B`
        let a: G = b * d_inv;

        Ok(BbsSignature { a, e })
    }

    /// Verifies a BBS MAC by recomputing B and checking that `A == (x + e)^{-1} * B`.
    ///
    /// # Parameters
    /// - x: the secret key scalar
    /// - attributes: the attributes to be verified
    /// - mac: the MAC to be verified
    ///
    /// # Returns
    /// - `Ok(())`: the MAC is valid
    /// - `Err(BbsSignatureError::InputLengthMismatch)`: number of attributes does not match
    ///   the number of generators
    /// - `Err(BbsSignatureError::VerificationFailed)`: computed value does not match the provided MAC
    ///
    /// # Example
    /// ```rust
    /// use bbs_mac_vs_sig::{BbsSignatureParams, BbsSignature};
    /// use bls12_381::Scalar;
    /// use bls12_381::G1Projective;
    /// use ff::Field;
    ///
    /// let mut rng = rand::thread_rng();
    /// let num_attributes = 5;
    /// let params = BbsSignatureParams::<G1Projective>::new(num_attributes);
    /// let x = Scalar::random(&mut rng);
    ///
    /// let mut attributes = Vec::with_capacity(num_attributes);
    /// for _ in 0..num_attributes {
    ///     attributes.push(Scalar::random(&mut rng));
    /// }
    ///
    /// let mac = params.sign(&x, &attributes, &mut rng).unwrap();
    /// params.verify(&x, &attributes, &mac).unwrap();
    /// ```
    pub fn verify(
        &self,
        x: &G::Scalar,
        attributes: &[G::Scalar],
        mac: &BbsSignature<G>,
    ) -> Result<(), BbsSignatureError> {
        if attributes.len() != self.h_generators.len() {
            return Err(BbsSignatureError::InputLengthMismatch);
        }
        let d = *x + mac.e;
        let d_inv: G::Scalar =
            Option::<G::Scalar>::from(d.invert()).ok_or(BbsSignatureError::VerificationFailed)?;

        let b: G = self.g_generator
            + attributes
                .iter()
                .zip(self.h_generators.iter())
                .map(|(m, h)| (*h) * (*m))
                .sum::<G>();

        let a_prime: G = b * d_inv;
        if a_prime == mac.a {
            Ok(())
        } else {
            Err(BbsSignatureError::VerificationFailed)
        }
    }
}

pub struct BbsPublicKey {
    public_key: G2Projective,
}

/// Creates a BBS public key from a private key scalar.
impl BbsPublicKey {
    pub fn new(private_key: Bls12_381Scalar) -> Self {
        Self {
            public_key: private_key * G2Projective::generator(),
        }
    }
}

impl BbsSignatureParams<G1Projective> {
    /// Verifies a BBS signature against a public key and a set of attributes
    ///
    /// This function verifies the pairing equation:
    /// `e(A, g2) == e(C, PK)`
    ///
    /// This function checks if the provided signature `A` is a valid
    /// BLS signature on the commitment `C = g1 + h_1*attr_1 + ... + h_n*attr_n`.
    ///
    /// Pairings are always between two groups (g2, g1). The signature lives in g1, which
    /// gives shorter signatures, and the public key lives in g2. We could also change the order
    /// if we want smaller public keys.
    ///
    /// If the public key `PK = g2^x` and the signature `A = C^x` (where `x` is the
    /// secret key), the equation holds:
    ///
    /// `e(C^x, g2) == e(C, g2^x)`
    /// `e(C, g2)^x == e(C, g2)^x`
    ///
    /// # Parameters
    /// - `pk`: The `BbsPublicKey` of the signer, containing an element in G2.
    /// - `attributes`: A slice of scalars (`Bls12_381Scalar`) representing the attributes.
    /// - `signature`: The `BbsSignature` to verify, containing an element `A` in G1.
    /// - `params`: the BBS signature parameters
    ///
    /// # Returns
    /// - `true`: the signature is valid
    /// - `false` if the signature is invalid or if the number of attributes
    ///   does not match the number of 'h' generators.
    ///
    /// **Important**: This is a **BLS signature on a commitment**, not a
    /// standard IETF BBS signature. A standard BBS signature involves two
    /// signature elements `(A, e)` and a scalar `s`, and uses a different
    /// verification equation.
    ///
    /// # Example
    /// ```rust
    /// use bbs_mac_vs_sig::{BbsSignatureParams, BbsSignature, BbsPublicKey};
    /// use bls12_381::Scalar;
    /// use bls12_381::G1Projective;
    /// use bls12_381::G2Projective;
    /// use ff::Field;
    /// use group::Curve;
    ///
    /// let mut rng = rand::thread_rng();
    /// let num_attributes = 5;
    /// let params = BbsSignatureParams::<G1Projective>::new(num_attributes);
    /// let x = Scalar::random(&mut rng);
    /// let pk = BbsPublicKey::new(x);
    ///
    /// let mut attributes = Vec::with_capacity(num_attributes);
    /// for _ in 0..num_attributes {
    ///     attributes.push(Scalar::random(&mut rng));
    /// }
    ///
    /// let mac = params.sign(&x, &attributes, &mut rng).unwrap();
    /// params.verify_with_pk(&pk, &attributes, &mac).unwrap();
    /// ```
    pub fn verify_with_pk(
        &self,
        pk: &BbsPublicKey,
        attributes: &[Bls12_381Scalar],
        signature: &BbsSignature<G1Projective>,
    ) -> Result<bool, BbsSignatureError> {
        if attributes.len() != self.h_generators.len() {
            return Err(BbsSignatureError::InputLengthMismatch);
        }

        // recompute commitment
        let attr: G1Projective = self.g_generator
            + attributes
                .iter()
                .zip(self.h_generators.iter())
                .map(|(m, h)| (*h) * (*m))
                .sum::<G1Projective>();

        // e(A, g2*x + g2*e) == e(attr, g2)
        let lhs = pairing(
            &signature.a.to_affine(),
            &(pk.public_key + G2Projective::generator() * signature.e).to_affine(),
        );
        let rhs = pairing(&attr.to_affine(), &G2Projective::generator().to_affine());

        if lhs == rhs {
            Ok(true)
        } else {
            Err(BbsSignatureError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::Scalar;
    use curve25519_dalek::{RistrettoPoint, Scalar as RistrettoScalar};

    /// Signs random attributes and verifies the MAC using the same parameters.
    /// This is a soundness test that should pass under normal conditions.

    #[test]
    fn sign_and_verify_succeeds_ristretto() {
        let mut rng = rand::thread_rng();
        let num_attributes = 5;
        let params = BbsSignatureParams::<RistrettoPoint>::new(num_attributes);
        let x = RistrettoScalar::random(&mut rng);

        let attributes: Vec<RistrettoScalar> =
            std::iter::repeat_with(|| RistrettoScalar::random(&mut rng))
                .take(num_attributes)
                .collect();

        let mac: BbsSignature<RistrettoPoint> = params.sign(&x, &attributes, &mut rng).unwrap();
        params.verify(&x, &attributes, &mac).unwrap();
    }

    /// Fails verification when wrong key is used for verification.
    #[test]
    fn wrong_key_fails_ristretto() {
        let mut rng = rand::thread_rng();
        let num_attributes = 3;
        let params = BbsSignatureParams::<RistrettoPoint>::new(num_attributes);
        let x = RistrettoScalar::random(&mut rng);
        let y = RistrettoScalar::random(&mut rng);

        let attributes: Vec<RistrettoScalar> =
            std::iter::repeat_with(|| RistrettoScalar::random(&mut rng))
                .take(num_attributes)
                .collect();

        let mac = params.sign(&x, &attributes, &mut rng).unwrap();

        // Tamper one message
        let mut tampered = attributes.clone();
        tampered[0] += RistrettoScalar::ONE;

        let res = params.verify(&y, &tampered, &mac);
        assert!(matches!(res, Err(BbsSignatureError::VerificationFailed)));
    }

    /// Fails verification when attributes are tampered after signing.
    #[test]
    fn tampered_attribute_fails_ristretto() {
        let mut rng = rand::thread_rng();
        let num_attributes = 3;
        let params = BbsSignatureParams::<RistrettoPoint>::new(num_attributes);
        let x = RistrettoScalar::random(&mut rng);

        let attributes: Vec<RistrettoScalar> =
            std::iter::repeat_with(|| RistrettoScalar::random(&mut rng))
                .take(num_attributes)
                .collect();
        let mac = params.sign(&x, &attributes, &mut rng).unwrap();

        // Tamper one attribute
        let mut tampered = attributes.clone();
        tampered[0] += RistrettoScalar::ONE;

        let res = params.verify(&x, &tampered, &mac);
        assert!(matches!(res, Err(BbsSignatureError::VerificationFailed)));
    }

    /// Returns an error when the number of attributes does not match the parameters.
    #[test]
    fn length_mismatch_errors_ristretto() {
        let mut rng = rand::thread_rng();
        let num_attributes = 4;
        let params = BbsSignatureParams::<RistrettoPoint>::new(num_attributes);
        let x = RistrettoScalar::random(&mut rng);

        // Use different number of attributes than params expect
        let wrong_len = num_attributes + 1;
        let attributes: Vec<RistrettoScalar> =
            std::iter::repeat_with(|| RistrettoScalar::random(&mut rng))
                .take(wrong_len)
                .collect();

        let res = params.sign(&x, &attributes, &mut rng);
        assert!(matches!(res, Err(BbsSignatureError::InputLengthMismatch)));
    }

    /// Signs random attributes and verifies the MAC using the same parameters.
    /// This is a soundness test that should pass under normal conditions.
    #[test]
    fn sign_and_verify_succeeds_bls12_381() {
        let mut rng = rand::thread_rng();
        let num_attributes = 5;
        let params = BbsSignatureParams::<G1Projective>::new(num_attributes);
        let x = Bls12_381Scalar::random(&mut rng);

        let attributes: Vec<Bls12_381Scalar> =
            std::iter::repeat_with(|| Bls12_381Scalar::random(&mut rng))
                .take(num_attributes)
                .collect();

        let mac = params.sign(&x, &attributes, &mut rng).unwrap();
        params.verify(&x, &attributes, &mac).unwrap();
    }

    /// Fails verification when wrong key is used for verification.
    #[test]
    fn wrong_key_fails_bls12_381() {
        let mut rng = rand::thread_rng();
        let num_attributes = 3;
        let params = BbsSignatureParams::<G1Projective>::new(num_attributes);
        let x = Bls12_381Scalar::random(&mut rng);
        let y = Bls12_381Scalar::random(&mut rng);

        let mut attributes = Vec::with_capacity(num_attributes);
        for _ in 0..num_attributes {
            attributes.push(Scalar::random(&mut rng));
        }

        let mac = params.sign(&x, &attributes, &mut rng).unwrap();

        // Tamper one message
        let mut tampered = attributes.clone();
        tampered[0] += Scalar::one();

        let res = params.verify(&y, &tampered, &mac);
        assert!(matches!(res, Err(BbsSignatureError::VerificationFailed)));
    }

    /// Fails verification when attributes are tampered after signing.
    #[test]
    fn tampered_attribute_fails_bls12_381() {
        let mut rng = rand::thread_rng();
        let num_attributes = 3;
        let params = BbsSignatureParams::<G1Projective>::new(num_attributes);
        let x = Bls12_381Scalar::random(&mut rng);

        // Use scalars
        let attributes: Vec<Bls12_381Scalar> =
            std::iter::repeat_with(|| Bls12_381Scalar::random(&mut rng))
                .take(num_attributes)
                .collect();

        let mac = params.sign(&x, &attributes, &mut rng).unwrap();

        // Tamper one attribute (scalar arithmetic)
        let mut tampered = attributes.clone();
        tampered[0] += Bls12_381Scalar::one();

        let res = params.verify(&x, &tampered, &mac);
        assert!(matches!(res, Err(BbsSignatureError::VerificationFailed)));
    }

    /// Returns an error when the number of attributes does not match the parameters.
    #[test]
    fn length_mismatch_errors_bls12_381() {
        let mut rng = rand::thread_rng();
        let num_attributes = 4;
        let params = BbsSignatureParams::<G1Projective>::new(num_attributes);
        let x = Bls12_381Scalar::random(&mut rng);

        // Use different number of attributes than params expect
        let wrong_len = num_attributes + 1;
        let attributes: Vec<Bls12_381Scalar> =
            std::iter::repeat_with(|| Bls12_381Scalar::random(&mut rng))
                .take(wrong_len)
                .collect();

        let res = params.sign(&x, &attributes, &mut rng);
        assert!(matches!(res, Err(BbsSignatureError::InputLengthMismatch)));
    }
}
