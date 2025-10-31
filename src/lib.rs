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
use std::collections::HashSet;
use std::marker::PhantomData;

use curve25519_dalek::{
    RistrettoPoint, Scalar as RistrettoScalar, ristretto::RistrettoBasepointTable,
};

/// A BBS Signature with the following components:
/// - `a`: the signature value `A = (x + e)^-1 * (G + m1*H1 + ... + ml*Hl)` for `l` attributes
/// - `e`: the random scalar used for the signature
/// the signature is only privately verifiable when not using pairings (i.e. needs a private key for verification)
#[derive(Debug)]
pub struct BbsSignature<G: Group> {
    a: G,
    e: G::Scalar,
}

#[derive(Debug)]
pub enum BbsSignatureError {
    /// thrown when the number of attributes does not match the number of generators
    InputLengthMismatch,
    /// thrown when the inverse of (x + e) cannot be computed (e.g. when x + e = 0)
    VerificationInverseFailed,
    /// thrown when the verification fails (e.g. when the given
    /// `A` != `(x + e)^-1 * (G + m1*H1 + ... + ml*Hl)`)
    VerificationFailed,
}

/// System parameters that define the cryptographic setup for the BBS scheme
///
/// The generators are going to be used throughout the protocol. The number of
/// generators depends on the number of attributes the BBS scheme is supposed to sign.
#[derive(Clone, Debug)]
pub struct BbsSignatureParams<G: Group> {
    h_generators: Vec<G>,
    g_generator: G,
}

impl<G: Group> BbsSignatureParams<G> {
    /// Generates deterministic parameters for the BBS scheme based on the `num_attributes` parameter:
    ///
    /// # Arguments
    /// - `num_attributes`: the number of attributes to be signed
    /// - `rng`: a random number generator
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
    /// let mut attributes = Vec::with_capacity(num_attributes);
    /// for _ in 0..num_attributes {
    ///     attributes.push(Bls12_381Scalar::random(&mut rng));
    /// }
    ///
    /// let mac = params.sign(&x, &attributes, &mut rng).unwrap();
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

        // Compute the scalar inverse: (x + e)^-1.
        let mut d: G::Scalar = *x + e; // d = x + e
        // We loop, re-sampling 'e' until (x + e) is non-zero and we get an inverse.
        let d_inv: G::Scalar = loop {
            // Attempt to compute the inverse.
            // ff::Field::invert returns subtle::CtOption<Self>.
            let inv = d.invert();
            if bool::from(inv.is_some()) {
                // Success! The inverse exists.
                break inv.unwrap();
            } else {
                // (x + e) was zero. Sample a new 'e' and the loop will retry.
                e = G::Scalar::random(&mut *rng);
                d = *x + e;
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
    /// - `Err(BbsMacError::InputLengthMismatch)`: number of attributes does not match number of generators
    /// - `Err(BbsMacError::VerificationFailed)`: computed value does not match the provided MAC
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

// Represents a BBS Proof
pub struct BbsProof {
    attributes: Vec<G1Projective>,
    signatures: Vec<G1Projective>,
    signature: BbsSignature<G1Projective>,
}

pub struct BbsPublicKey {
    public_key: G2Projective,
}

impl BbsPublicKey {
    pub fn new(private_key: Bls12_381Scalar) -> Self {
        Self {
            public_key: private_key * G2Projective::generator(),
        }
    }
}

impl BbsProof {
    ///
    /// Verifies a BBS signature against a public key and a set of attributes
    ///
    /// This function verifies the pairing equation:
    /// `e(A, g2) == e(C, PK)`
    ///
    /// Where:
    ///
    /// This function checks if the provided signature `A` is a valid
    /// BLS signature on the commitment `C = g1 + h_1*attr_1 + ... + h_n*attr_n`.
    ///
    /// If the public key `PK = g2^x` and the signature `A = C^x` (where `x` is the
    /// secret key), the equation holds:
    ///
    /// `e(C^x, g2) == e(C, g2^x)`
    /// `e(C, g2)^x == e(C, g2)^x`
    ///
    /// # Parameters
    /// - `pk`: The `BbsPublicKey` of the signer, containing an element in G2.
    /// - `attributes`: A slice of scalars (`Bls12_381Scalar`) representing the messages.
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
    /// use bbs_mac_vs_sig::{BbsSignatureParams, BbsSignature};
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
    ///
    /// let mut attributes = Vec::with_capacity(num_attributes);
    /// for _ in 0..num_attributes {
    ///     attributes.push(Scalar::random(&mut rng));
    /// }
    ///
    /// let mac = params.sign(&x, &attributes, &mut rng).unwrap();
    /// params.verify(&x, &attributes, &mac).unwrap();
    /// ```
    pub fn verify_with_pk(
        pk: &BbsPublicKey,
        attributes: &[Bls12_381Scalar],
        signature: &BbsSignature<G1Projective>,
        params: &BbsSignatureParams<G1Projective>,
    ) -> bool {
        // note:pairings are always between two groups (g2, g1). The signature lives in g1, which
        // gives shorter signatures, and the public key lives in g2. We could also change it
        // if we want smaller public keys

        // first, recompute the attributes (since we have a vector)
        let attr: G1Projective = params.g_generator
            + attributes
                .iter()
                .zip(params.h_generators.iter())
                .map(|(m, h)| (*h) * (*m))
                .sum::<G1Projective>();

        // TODO compute pairing between message and public key
        let e1 = pairing(&attr.to_affine(), &pk.public_key.to_affine());
        let e2 = pairing(
            &signature.a.to_affine(),
            &G2Projective::generator().to_affine(),
        );

        if e1 == e2 {
            return true;
        }
        false
    }

    //    pub fn show_partial(
    //        pk: BbsPublicKey,
    //        signature: BbsSignature<G1Projective>,
    //        attributes: &[Bls12_381Scalar],
    //        bbs_params: &BbsSignatureParams<G1Projective>,
    //        disclosed_indices: &[usize],
    //    ) -> Result<BbsProof, BbsSignatureError> {
    //        // validatate parameters
    //        if attributes.len() != bbs_params.h_generators.len() {
    //            return Err(BbsSignatureError::InputLengthMismatch);
    //        }
    //        // Validate bounds
    //        if disclosed_indices.iter().any(|&i| i >= attributes.len()) {
    //            return Err(BbsSignatureError::VerificationFailed);
    //        }

    //        let mut ctr_undisclosed=0;
    //        let mut ctr_disclosed=0;
    //        let mut undisclosed_indices=Vec<usize>().with_capacity(attributes.len()-disclosed_indices.len());
    //        let mut disclosed_attributes=Vec<Bls12_381Scalar>().with_capacity(disclosed_indices.len());
    //        let mut undisclosed_attributes=Vec<Bls12_381Scalar>().with_capacity(attributes.len()-disclosed_indices.len());
    // / this loop takes `disclosed_indices` and fills `disclosed_attributes` with the attributes to be disclosed,
    // / and also generates a vector `undisclosed_attributes` and `undisclosed_indices`
    //        for i in range(0..attributes.len()){
    //            while(disclosed_indices[ctr_disclosed]>i && i < attributes.len()){
    //                undisclosed_indices.push(i);
    //                undisclosed_message.push(messsages[i]);
    //                ctr_undisclosed+=1;
    //                i+=1;
    //            }
    //                disclosed_indices.push(messsages[i]);
    //                ctr_disclosed+=1;
    //        }

    //        unimplemented!()
    //    }

    //    // - result, either VALID or INVALID.
    //    pub fn verify_partial() -> bool {
    //        true
    //    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Signs random attributes and verifies the MAC using the same parameters.
    /// This is a soundness test that should pass under normal conditions.
    #[test]
    fn sign_and_verify_succeeds_ristretto() {
        let mut rng = rand::thread_rng();
        let num_attributes = 5;
        let params = BbsSignatureParams::<RistrettoPoint>::new(num_attributes);
        let x = RistrettoScalar::random(&mut rng);

        let mut attributes = Vec::with_capacity(num_attributes);
        for _ in 0..num_attributes {
            attributes.push(RistrettoScalar::random(&mut rng));
        }

        let mac: BbsSignature<RistrettoPoint> = params.sign(&x, &attributes, &mut rng).unwrap();
        params.verify(&x, &attributes, &mac).unwrap();
    }

    /// Fails verification when attributes are tampered after signing.
    #[test]
    fn tampered_message_fails_ristretto() {
        let mut rng = rand::thread_rng();
        let num_attributes = 3;
        let params = BbsSignatureParams::<RistrettoPoint>::new(num_attributes);
        let x = RistrettoScalar::random(&mut rng);

        let mut attributes = Vec::with_capacity(num_attributes);
        for _ in 0..num_attributes {
            attributes.push(RistrettoScalar::random(&mut rng));
        }

        let mac = params.sign(&x, &attributes, &mut rng).unwrap();

        // Tamper one message
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
        let mut attributes = Vec::with_capacity(wrong_len);
        for _ in 0..wrong_len {
            attributes.push(RistrettoScalar::random(&mut rng));
        }

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

        let mut attributes = Vec::with_capacity(num_attributes);
        for _ in 0..num_attributes {
            attributes.push(Bls12_381Scalar::random(&mut rng));
        }

        let mac = params.sign(&x, &attributes, &mut rng).unwrap();
        params.verify(&x, &attributes, &mac).unwrap();
    }

    /// Fails verification when attributes are tampered after signing.
    #[test]
    fn tampered_message_fails_bls12_381() {
        let mut rng = rand::thread_rng();
        let num_attributes = 3;
        let params = BbsSignatureParams::<G1Projective>::new(num_attributes);
        let x = Bls12_381Scalar::random(&mut rng);

        let mut attributes = Vec::with_capacity(num_attributes);
        for _ in 0..num_attributes {
            attributes.push(Bls12_381Scalar::random(&mut rng));
        }

        let mac = params.sign(&x, &attributes, &mut rng).unwrap();

        // Tamper one message
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
        let mut attributes = Vec::with_capacity(wrong_len);
        for _ in 0..wrong_len {
            attributes.push(Bls12_381Scalar::random(&mut rng));
        }

        let res = params.sign(&x, &attributes, &mut rng);
        assert!(matches!(res, Err(BbsSignatureError::InputLengthMismatch)));
    }
}
