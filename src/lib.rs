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

/// A BBS Signature with the following components:
/// - `a`: the signature value `A = (x + e)^-1 * (G + m1*H1 + ... + ml*Hl)` for `l` messages
/// - `e`: the random scalar used for the signature
/// the signature is only privately verifiable when not using pairings (i.e. needs a private key for verification)
#[derive(Debug)]
pub struct BbsSignature<G: Group> {
    a: G,
    e: G::Scalar,
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

impl BbsProof {
    pub fn show_partial(
        pk: G1Projective,
        signature: BbsSignature<G1Projective>,
        messages: &[Bls12_381Scalar],
        bbs_params: &BbsSignatureParams<G1Projective>,
        disclosed_indices: &[usize],
    ) -> Result<BbsProof, BbsSignatureError> {
        if messages.len() != bbs_params.h_generators.len() {
            return Err(BbsSignatureError::InputLengthMismatch);
        }

        // 1) Validate bounds
        if disclosed_indices.iter().any(|&i| i >= messages.len()) {
            return Err(BbsSignatureError::VerificationFailed);
        }

        // TODO Optional: reject duplicates
        // 9.  undisclosed_indexes = (0, 1, ..., L - 1) \ disclosed_indexes
        let disclosed_set: HashSet<usize> = disclosed_indices.iter().copied().collect();
        if disclosed_set.len() != disclosed_indices.len() {
            return Err(BbsSignatureError::VerificationFailed);
        }

        // 2) Compute complement in ascending order
        // let undisclosed_indices: Vec<usize> =
        //     (0..l).filter(|i| !disclosed_set.contains(i)).collect();
        // TODO do we need
        // (messages[i1], ..., messages[iR])
        // (messages[j1], ..., messages[jU])
        //
        //
        //  let random_scalars = Vec<Bls12_381Scalar>::with_capacity(5 + undisclosed_indices.len());

        //  // 2. B = P1  * domain + H_1 * msg_1 + ... + H_L * msg_L
        //  let r1=Bls12_381Scalar::random(&mut rng);
        //  let r2=Bls12_381Scalar::random(&mut rng);
        //  let b = bbs_params.g_generator
        //      + messages
        //          .iter()
        //          .zip(bbs_params.h_generators.iter())
        //          .map(|(m, h)| (*h) * (*m))
        //          .sum::<G1Projective>();
        //      let d=b*r2;
        //      let a_bar=signature.a*(r1*r2);
        //      let b_bar=d*r1-a_bar*signature.e;
        //      let t_1=a_bar*signature.e.invert().unwrap()+signature.a*r1.invert().unwrap();
        //      let h_undisclosed: Vec<G1Projective> = Vec::with_capacity(undisclosed_indices.len());
        //      for j in undisclosed_indices.iter() {
        //          h_undisclosed.push(bbs_params.h_generators[*j]);
        //      }
        //      let t_2=d*r3.invert().unwrap();
        //      for i in range(len(undisclosed_indices.len())){
        //          t_2+=h_undisclosed[i]*messages[undisclosed_indices[i]];
        //      }

        // 8. return (Abar, Bbar, D, T1, T2, domain)

        // compute  challenge

        // Inputs:
        // - init_res (REQUIRED), vector representing the value returned after
        //                        initializing the proof generation or verification
        //                        operations, consisting of 5 points of G1 and a
        //                        scalar value, in that order.
        // - disclosed_messages (OPTIONAL), vector of scalar values. If not
        //                                  supplied, it defaults to the empty
        //                                  array ("()").
        // - disclosed_indexes (OPTIONAL), vector of non-negative integers in
        //                                 ascending order. If not supplied, it
        //                                 defaults to the empty array ("()").
        // - ph (OPTIONAL), an octet string. If not supplied, it must default to
        //                  the empty octet string ("").
        // - api_id (OPTIONAL), an octet string. If not supplied it defaults to the
        //                      empty octet string ("").
        //
        // Outputs:
        //
        // - challenge, a scalar.
        //
        // Definitions:
        //
        // 1. hash_to_scalar_dst, an octet string representing the domain
        //                        separation tag: api_id || "H2S_" where "H2S_" is
        //                        an ASCII string comprised of 4 bytes.
        //
        // Deserialization:
        //
        // Looker, et al.           Expires 8 January 2026                [Page 35]
        // Internet-Draft          The BBS Signature Scheme               July 2025
        //
        // 1. R = length(disclosed_indexes)
        // 2. (i1, ..., iR) = disclosed_indexes
        // 3. if length(disclosed_messages) != R, return INVALID
        // 3. (msg_i1, ..., msg_iR) = disclosed_messages
        // 4. (Abar, Bbar, D, T1, T2, domain) = init_res
        //
        // ABORT if:
        //
        // 1. R > 2^64 - 1
        // 2. length(ph) > 2^64 - 1
        //
        // Procedure:
        //
        // 1. c_arr = (R, i1, msg_i1, i2, msg_i2, ..., iR, msg_iR, Abar, Bbar,
        //                                                       D, T1, T2, domain)
        // 2. c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
        // 3. return hash_to_scalar(c_octs, hash_to_scalar_dst)
        //
        // 4. challenge = ProofChallengeCalculate(init_res, disclosed_messages,
        //                                                  disclosed_indexes,
        //                                                  ph,
        //                                                  api_id)
        // 5. if challenge is INVALID, return INVALID
        // 6. proof = ProofFinalize(init_res, challenge, e, random_scalars,
        //                                                    undisclosed_messages)
        // 7. return proof

        unimplemented!()
    }

    // - result, either VALID or INVALID.
    pub fn verify_partial() -> bool {
        true
    }
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
