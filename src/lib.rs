//! Minimal BBS MAC over BLS12-381: parameters, signing, verification, and tests.
//!
//! This module provides a small, documented implementation suitable for examples
//! and experimentation. It is not audited; do not use in production.

use bls12_381::G1Projective;
use bls12_381::Scalar as Bls12_381Scalar;
use ff::Field; // For .invert() and .is_zero()
use group::Group; // For G1Projective ops (+, *, .generator())
use rand::RngCore;
use std::collections::HashSet;
use std::marker::PhantomData;

use curve25519_dalek::{
    RistrettoPoint, Scalar as RistrettoScalar, ristretto::RistrettoBasepointTable,
};

/*
use std::marker::PhantomData;

trait Group {}

struct Ristretto255;

impl Group for Ristretto255 {}

struct Bls12_381;

impl Group for Bls12_381 {}

struct Bbs<G> {
    phantom: PhantomData<G>,
}

struct BbsSignature<G> {
    phantom: PhantomData<G>,
}

impl<G: Group> Bbs<G> {
    pub fn sign(&self, msg: &[&[u8]]) -> BbsSignature<G> {
        todo!()
    }
}

impl Bbs<Ristretto255> {
    pub fn private_verify(&self, msg: &[&[u8]], sig: &BbsSignature<Ristretto255>) -> bool {
        todo!()
    }
}

impl Bbs<Bls12_381> {
    pub fn public_verify(&self, msg: &[&[u8]], sig: &BbsSignature<Ristretto255>) -> bool {
        todo!()
    }
}
*/

// Represents a BBS Proof
pub struct BbsProof {
    pub abar: G1Projective,
    pub bbar: G1Projective,
    pub d: G1Projective,
    pub e_hat: Bls12_381Scalar,
    pub r1_hat: Bls12_381Scalar,
    pub r3_hat: Bls12_381Scalar,
    pub commitments: Vec<Bls12_381Scalar>,
    pub challenge: Bls12_381Scalar, // This is `cp` in the draft
}

#[derive(Debug)]
pub enum BbsSignatureError {
    /// thrown when the number of messages does not match the number of generators
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
/// generators depends on the number of messages the BBS scheme is supposed to sign.
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
    /// - `messages`: the messages to be signed
    /// - `rng`: a random number generator
    ///
    /// # Returns
    /// - `Ok(BbsSignature)`: the computed BBS MAC
    /// - `Err(BbsSignatureError::InputLengthMismatch)`: an error if the number of messages
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
    /// let num_messages = 5;
    /// let params = BbsSignatureParams::<G1Projective>::new(num_messages);
    /// let x = Bls12_381Scalar::random(&mut rng);
    /// let mut messages = Vec::with_capacity(num_messages);
    /// for _ in 0..num_messages {
    ///     messages.push(Bls12_381Scalar::random(&mut rng));
    /// }
    ///
    /// let mac = params.sign(&x, &messages, &mut rng).unwrap();
    /// ```
    pub fn sign(
        &self,
        x: &G::Scalar,
        messages: &[G::Scalar],
        rng: &mut impl RngCore,
    ) -> Result<BbsSignature<G>, BbsSignatureError> {
        if messages.len() != self.h_generators.len() {
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

        // Compute the multi-scalar multiplication with the generators and messages:
        // `B = G + m1*H1 + ... + ml*Hl`
        // TODO do we have some form of multi-exp here?
        let b: G = self.g_generator
            + messages
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

/// A BBS Signature with the following components:
/// - `a`: the signature value `A = (x + e)^-1 * (G + m1*H1 + ... + ml*Hl)` for `l` messages
/// - `e`: the random scalar used for the signature
/// the signature is only privately verifiable when not using pairings (i.e. needs a private key for verification)
#[derive(Debug)]
pub struct BbsSignature<G: Group> {
    a: G,
    e: G::Scalar,
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Signs random messages and verifies the MAC using the same parameters.
    /// This is a soundness test that should pass under normal conditions.
    #[test]
    fn sign_and_verify_succeeds_ristretto() {
        let mut rng = rand::thread_rng();
        let num_messages = 5;
        let params = BbsSignatureParams::<RistrettoPoint>::new(num_messages);
        let x = RistrettoScalar::random(&mut rng);

        let mut messages = Vec::with_capacity(num_messages);
        for _ in 0..num_messages {
            messages.push(RistrettoScalar::random(&mut rng));
        }

        let mac: BbsSignature<RistrettoPoint> = params.sign(&x, &messages, &mut rng).unwrap();
        params.verify(&x, &messages, &mac).unwrap();
    }

    /// Fails verification when messages are tampered after signing.
    #[test]
    fn tampered_message_fails_ristretto() {
        let mut rng = rand::thread_rng();
        let num_messages = 3;
        let params = BbsSignatureParams::<RistrettoPoint>::new(num_messages);
        let x = RistrettoScalar::random(&mut rng);

        let mut messages = Vec::with_capacity(num_messages);
        for _ in 0..num_messages {
            messages.push(RistrettoScalar::random(&mut rng));
        }

        let mac = params.sign(&x, &messages, &mut rng).unwrap();

        // Tamper one message
        let mut tampered = messages.clone();
        tampered[0] += RistrettoScalar::ONE;

        let res = params.verify(&x, &tampered, &mac);
        assert!(matches!(res, Err(BbsSignatureError::VerificationFailed)));
    }

    /// Returns an error when the number of messages does not match the parameters.
    #[test]
    fn length_mismatch_errors_ristretto() {
        let mut rng = rand::thread_rng();
        let num_messages = 4;
        let params = BbsSignatureParams::<RistrettoPoint>::new(num_messages);
        let x = RistrettoScalar::random(&mut rng);

        // Use different number of messages than params expect
        let wrong_len = num_messages + 1;
        let mut messages = Vec::with_capacity(wrong_len);
        for _ in 0..wrong_len {
            messages.push(RistrettoScalar::random(&mut rng));
        }

        let res = params.sign(&x, &messages, &mut rng);
        assert!(matches!(res, Err(BbsSignatureError::InputLengthMismatch)));
    }

    /// Signs random messages and verifies the MAC using the same parameters.
    /// This is a soundness test that should pass under normal conditions.
    #[test]
    fn sign_and_verify_succeeds_bls12_381() {
        let mut rng = rand::thread_rng();
        let num_messages = 5;
        let params = BbsSignatureParams::<G1Projective>::new(num_messages);
        let x = Bls12_381Scalar::random(&mut rng);

        let mut messages = Vec::with_capacity(num_messages);
        for _ in 0..num_messages {
            messages.push(Bls12_381Scalar::random(&mut rng));
        }

        let mac = params.sign(&x, &messages, &mut rng).unwrap();
        params.verify(&x, &messages, &mac).unwrap();
    }

    /// Fails verification when messages are tampered after signing.
    #[test]
    fn tampered_message_fails_bls12_381() {
        let mut rng = rand::thread_rng();
        let num_messages = 3;
        let params = BbsSignatureParams::<G1Projective>::new(num_messages);
        let x = Bls12_381Scalar::random(&mut rng);

        let mut messages = Vec::with_capacity(num_messages);
        for _ in 0..num_messages {
            messages.push(Bls12_381Scalar::random(&mut rng));
        }

        let mac = params.sign(&x, &messages, &mut rng).unwrap();

        // Tamper one message
        let mut tampered = messages.clone();
        tampered[0] += Bls12_381Scalar::one();

        let res = params.verify(&x, &tampered, &mac);
        assert!(matches!(res, Err(BbsSignatureError::VerificationFailed)));
    }

    /// Returns an error when the number of messages does not match the parameters.
    #[test]
    fn length_mismatch_errors_bls12_381() {
        let mut rng = rand::thread_rng();
        let num_messages = 4;
        let params = BbsSignatureParams::<G1Projective>::new(num_messages);
        let x = Bls12_381Scalar::random(&mut rng);

        // Use different number of messages than params expect
        let wrong_len = num_messages + 1;
        let mut messages = Vec::with_capacity(wrong_len);
        for _ in 0..wrong_len {
            messages.push(Bls12_381Scalar::random(&mut rng));
        }

        let res = params.sign(&x, &messages, &mut rng);
        assert!(matches!(res, Err(BbsSignatureError::InputLengthMismatch)));
    }
}
