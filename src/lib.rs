//! Minimal BBS MAC over BLS12-381: parameters, signing, verification, and tests.
//!
//! This module provides a small, documented implementation suitable for examples
//! and experimentation. It is not audited; do not use in production.

use bls12_381::G1Projective;
use bls12_381::Scalar;
use ff::Field; // For .invert() and .is_zero()
use group::Group; // For G1Projective ops (+, *, .generator())
use rand::RngCore;

/// System parameters that define the cryptographic setup for the BBS scheme.
///
/// The generators are going to be used throughout the protocol. The number of
/// generators depends on the number of attributes the BBS scheme is supposed to sign.
/// TODO use generic parameters with hash-to-curve (e.g. a counter)
#[derive(Clone, Debug)]
pub struct BbsParams<G: Group> {
    h_generators: Vec<G>,
    g_generator: G,
}

impl BbsParams<G1Projective> {
    /// Generates parameters for the BBS scheme based on the desired number of attributes to sign.
    ///
    /// # Arguments
    /// - `num_attributes`: the number of attributes to be signed
    /// - `rng`: a random number generator
    ///
    /// # Returns
    /// - `BbsParams`: the system parameters
    ///
    /// # Example
    /// ```rust
    /// use bbs_mac_vs_sig::BbsParams;
    /// let mut rng = rand::thread_rng();
    /// let num_attributes = 5;
    /// let params = BbsParams::new(num_attributes, &mut rng);
    /// ```
    pub fn new(num_attributes: usize, rng: &mut impl RngCore) -> Self {
        let g_generator = G1Projective::generator();
        let h_generators = std::iter::repeat_with(|| G1Projective::random(&mut *rng)).take(num_attributes).collect();
        Self {
            h_generators,
            g_generator,
        }
    }
}

/// A BBS MAC (Message Authentication Code) with the following components:
/// - `a`: the MAC value `A = (x + e)^-1 * (G + m1*H1 + ... + ml*Hl)` for `l` attributes
/// - `e`: the random scalar used for the MAC
#[derive(Debug)]
pub struct BbsMac {
    a: G1Projective,
    e: Scalar,
}

#[derive(Debug)]
pub enum BbsMacError {
    /// thrown when the number of attributes does not match the number of generators
    InputLengthMismatch,
    /// thrown when the inverse of (x + e) cannot be computed (e.g. when x + e = 0)
    VerificationInverseFailed,
    /// thrown when the verification fails (e.g. when the given
    /// `A` != `(x + e)^-1 * (G + m1*H1 + ... + ml*Hl)`)
    VerificationFailed,
}

impl BbsMac {
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
    /// - `Ok(BbsMac)`: the computed BBS MAC
    /// - `Err(BbsMacError::InputLengthMismatch)`: an error if the number of attributes
    ///   does not match the number of generators
    ///
    /// # Example
    /// ```rust
    /// use bbs_mac_vs_sig::{BbsParams, BbsMac};
    /// use bls12_381::Scalar;
    /// use ff::Field;
    ///
    /// let mut rng = rand::thread_rng();
    /// let num_attributes = 5;
    /// let params = BbsParams::new(num_attributes, &mut rng);
    /// let x = Scalar::random(&mut rng);
    /// let mut attributes = Vec::with_capacity(num_attributes);
    /// for _ in 0..num_attributes {
    ///     attributes.push(Scalar::random(&mut rng));
    /// }
    ///
    /// let mac = BbsMac::sign(&x, &attributes, &params, &mut rng).unwrap();
    /// BbsMac::verify(&x, &attributes, &mac, &params).unwrap();
    /// ```
    pub fn sign(
        x: &Scalar,
        attributes: &[Scalar],
        bbs_params: &BbsParams<G1Projective>,
        rng: &mut impl RngCore,
    ) -> Result<BbsMac, BbsMacError> {
        if attributes.len() != bbs_params.h_generators.len() {
            return Err(BbsMacError::InputLengthMismatch);
        }

        // generate random e for the MAC
        let mut e: Scalar = Scalar::random(&mut *rng);

        // Compute the scalar inverse: (x + e)^-1.
        let mut d: Scalar = *x + e; // d = x + e
        // We loop, re-sampling 'e' until (x + e) is non-zero and we get an inverse.
        let d_inv: Scalar = loop {
            // Attempt to compute the inverse.
            // ff::Field::invert returns subtle::CtOption<Self>.
            let inv = d.invert();
            if bool::from(inv.is_some()) {
                // Success! The inverse exists.
                break inv.unwrap();
            } else {
                // (x + e) was zero. Sample a new 'e' and the loop will retry.
                e = Scalar::random(&mut *rng);
                d = *x + e;
            }
        };

        // Compute the multi-scalar multiplication with the generators and attributes:
        // `B = G + m1*H1 + ... + ml*Hl`
        // TODO do we have some form of multi-exp here?
        let b: G1Projective = bbs_params.g_generator
            + attributes
                .iter()
                .zip(bbs_params.h_generators.iter())
                .map(|(m, h)| (*h) * (*m))
                .sum::<G1Projective>();

        // Compute the final signature component `A = d_inv * B`
        let a: G1Projective = b * d_inv;

        Ok(Self { a, e })
    }

    /// Verifies a BBS MAC by recomputing B and checking that `A == (x + e)^{-1} * B`.
    ///
    /// # Parameters
    /// - x: the secret key scalar
    /// - attributes: the attributes to be verified
    /// - mac: the MAC to be verified
    /// - bbs_params: the system parameters
    ///
    /// # Returns
    /// - `Ok(())`: the MAC is valid
    /// - `Err(BbsMacError::VerificationInverseFailed)`: could not invert (x + e)
    /// - `Err(BbsMacError::InputLengthMismatch)`: number of attributes does not match number of generators
    /// - `Err(BbsMacError::VerificationFailed)`: computed value does not match the provided MAC
    ///
    /// # Example
    /// ```rust
    /// use bbs_mac_vs_sig::{BbsParams, BbsMac};
    /// use bls12_381::Scalar;
    /// use ff::Field;
    ///
    /// let mut rng = rand::thread_rng();
    /// let num_attributes = 5;
    /// let params = BbsParams::new(num_attributes, &mut rng);
    /// let x = Scalar::random(&mut rng);
    ///
    /// let mut attributes = Vec::with_capacity(num_attributes);
    /// for _ in 0..num_attributes {
    ///     attributes.push(Scalar::random(&mut rng));
    /// }
    ///
    /// let mac = BbsMac::sign(&x, &attributes, &params, &mut rng).unwrap();
    /// BbsMac::verify(&x, &attributes, &mac, &params).unwrap();
    /// ```
    pub fn verify(
        x: &Scalar,
        attributes: &[Scalar],
        mac: &BbsMac,
        bbs_params: &BbsParams<G1Projective>,
    ) -> Result<(), BbsMacError> {
        if attributes.len() != bbs_params.h_generators.len() {
            return Err(BbsMacError::InputLengthMismatch);
        }

        let inv = (x + mac.e).invert();
        if bool::from(inv.is_none()) {
            return Err(BbsMacError::VerificationInverseFailed);
        }

        let b: G1Projective = bbs_params.g_generator
            + attributes
                .iter()
                .zip(bbs_params.h_generators.iter())
                .map(|(m, h)| (*h) * (*m))
                .sum::<G1Projective>();

        let a_prime: G1Projective = b * inv.unwrap();
        if a_prime == mac.a {
            Ok(())
        } else {
            Err(BbsMacError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signs random attributes and verifies the MAC using the same parameters.
    /// This is a soundness test that should pass under normal conditions.
    #[test]
    fn sign_and_verify_succeeds() {
        let mut rng = rand::thread_rng();
        let num_attributes = 5;
        let params = BbsParams::new(num_attributes, &mut rng);
        let x = Scalar::random(&mut rng);

        let mut attributes = Vec::with_capacity(num_attributes);
        for _ in 0..num_attributes {
            attributes.push(Scalar::random(&mut rng));
        }

        let mac = BbsMac::sign(&x, &attributes, &params, &mut rng).unwrap();
        BbsMac::verify(&x, &attributes, &mac, &params).unwrap();
    }

    /// Fails verification when wrong key is used for verification.
    #[test]
    fn wrong_key_fails() {
        let mut rng = rand::thread_rng();
        let num_attributes = 3;
        let params = BbsParams::new(num_attributes, &mut rng);
        let x = Scalar::random(&mut rng);
        let y = Scalar::random(&mut rng);

        let mut attributes = Vec::with_capacity(num_attributes);
        for _ in 0..num_attributes {
            attributes.push(Scalar::random(&mut rng));
        }

        let mac = BbsMac::sign(&x, &attributes, &params, &mut rng).unwrap();

        // Tamper one message
        let mut tampered = attributes.clone();
        tampered[0] += Scalar::one();

        let res = BbsMac::verify(&y, &tampered, &mac, &params);
        assert!(matches!(res, Err(BbsMacError::VerificationFailed)));
    }

    /// Fails verification when attributes are tampered after signing.
    #[test]
    fn tampered_message_fails() {
        let mut rng = rand::thread_rng();
        let num_attributes = 3;
        let params = BbsParams::new(num_attributes, &mut rng);
        let x = Scalar::random(&mut rng);

        let mut attributes = Vec::with_capacity(num_attributes);
        for _ in 0..num_attributes {
            attributes.push(Scalar::random(&mut rng));
        }

        let mac = BbsMac::sign(&x, &attributes, &params, &mut rng).unwrap();

        // Tamper one message
        let mut tampered = attributes.clone();
        tampered[0] += Scalar::one();

        let res = BbsMac::verify(&x, &tampered, &mac, &params);
        assert!(matches!(res, Err(BbsMacError::VerificationFailed)));
    }

    /// Returns an error when the number of attributes does not match the parameters.
    #[test]
    fn length_mismatch_errors() {
        let mut rng = rand::thread_rng();
        let num_attributes = 4;
        let params = BbsParams::new(num_attributes, &mut rng);
        let x = Scalar::random(&mut rng);

        // Use different number of attributes than params expect
        let wrong_len = num_attributes + 1;
        let mut attributes = Vec::with_capacity(wrong_len);
        for _ in 0..wrong_len {
            attributes.push(Scalar::random(&mut rng));
        }

        let res = BbsMac::sign(&x, &attributes, &params, &mut rng);
        assert!(matches!(res, Err(BbsMacError::InputLengthMismatch)));
    }
}
