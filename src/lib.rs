#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(not(feature = "std"))]
extern crate alloc;

extern crate pairing;
extern crate rand;

use pairing::{CurveAffine, Engine, PrimeField, EncodedPoint};
use pairing::bls12_381::{Bls12, Fr, FrRepr, G1Compressed, G2Compressed};
use rand::{Rand, Rng};
#[cfg(feature = "std")]
use std::collections::{HashSet as Set};
#[cfg(not(feature = "std"))]
use alloc::collections::{BTreeSet as Set};

#[cfg(not(feature = "std"))]
mod std {
	pub use core::*;
	pub use alloc::vec;
	pub use alloc::string;
	pub use alloc::boxed;
	pub use alloc::borrow;
}

use std::vec::Vec;

#[derive(Debug, PartialEq)]
pub struct Signature<E: Engine> {
    s: E::G2,
}

impl Signature<Bls12> {
    pub fn to_compressed_bytes(&self) -> [u8; 96] {
        let mut ret = [0u8; 96];
        ret.copy_from_slice(&G2Compressed::from_affine(self.s.clone().into()).as_ref());
        ret
    }

    pub fn from_compressed_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 96 {
            return None;
        }
        let mut g2 = G2Compressed::empty();
        g2.as_mut().copy_from_slice(bytes);
        let affine = g2.into_affine().ok()?;

        Some(Self {
            s: affine.into(),
        })
    }
}

pub struct Secret<E: Engine> {
    x: E::Fr,
}

impl<E: Engine> Clone for Secret<E> {
    fn clone(&self) -> Self {
        Self {
            x: self.x.clone()
        }
    }
}

impl<E: Engine> Secret<E> {
    pub fn generate<R: Rng>(csprng: &mut R) -> Self {
        Secret {
            x: E::Fr::rand(csprng),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature<E> {
        let h = E::G2Affine::hash(message);
        Signature { s: h.mul(self.x) }
    }
}

impl Secret<Bls12> {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut ints = [0u64; 4];
        for (i, byte) in bytes.iter().enumerate() {
            let z = i / 8;
            if z >= ints.len() {
                return None
            }
            ints[z] |= (*byte as u64) << (i - z * 8);
        }
        Fr::from_repr(FrRepr(ints)).ok().map(|fr| Secret { x: fr })
    }
}

pub struct Public<E: Engine> {
    p_pub: E::G1,
}

impl<E: Engine> Clone for Public<E> {
    fn clone(&self) -> Self {
        Self {
            p_pub: self.p_pub.clone()
        }
    }
}

impl<E: Engine> Public<E> {
    pub fn from_secret(secret: &Secret<E>) -> Self {
        // TODO Decide on projective vs affine
        Public {
            p_pub: E::G1Affine::one().mul(secret.x),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &Signature<E>) -> bool {
        let h = E::G2Affine::hash(message);
        let lhs = E::pairing(E::G1Affine::one(), signature.s);
        let rhs = E::pairing(self.p_pub, h);
        lhs == rhs
    }
}

impl Public<Bls12> {
    pub fn to_compressed_bytes(&self) -> [u8; 48] {
        let mut ret = [0u8; 48];
        ret.copy_from_slice(&G1Compressed::from_affine(self.p_pub.clone().into()).as_ref());
        ret
    }

    pub fn from_compressed_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 48 {
            return None;
        }
        let mut g1 = G1Compressed::empty();
        g1.as_mut().copy_from_slice(bytes);
        let affine = g1.into_affine().ok()?;

        Some(Self {
            p_pub: affine.into(),
        })
    }
}

pub struct Pair<E: Engine> {
    pub secret: Secret<E>,
    pub public: Public<E>,
}

impl<E: Engine> Pair<E> {
    pub fn generate<R: Rng>(csprng: &mut R) -> Self {
        let secret = Secret::generate(csprng);
        let public = Public::from_secret(&secret);
        Pair { secret, public }
    }

    pub fn from_secret(secret: Secret<E>) -> Self {
        Pair {
            public: Public::from_secret(&secret),
            secret,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature<E> {
        self.secret.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature<E>) -> bool {
        self.public.verify(message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pairing::bls12_381::Bls12;
    use rand::{SeedableRng, XorShiftRng};

    #[test]
    fn test_sign_verify_short() {
        sign_verify(10);
    }
    #[test]
    #[ignore]
    fn test_sign_verify_long() {
        sign_verify(500);
    }
    fn sign_verify(loop_count: u32) {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        for i in 0..loop_count {
            let keypair = Pair::<Bls12>::generate(&mut rng);
            let message = format!(">16 character message {}", i);
            let sig = keypair.sign(&message.as_bytes());
            assert_eq!(keypair.verify(&message.as_bytes(), &sig), true);
        }
    }

    #[test]
    fn test_sign_verify_with_clone_pubic_short() {
        sign_verify_with_cloned_public(10);
    }
    #[test]
    #[ignore]
    fn test_sign_verify_with_clone_pubic_long() {
        sign_verify_with_cloned_public(500);
    }
    fn sign_verify_with_cloned_public(loop_count: u32) {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        for i in 0..loop_count {
            let keypair = Pair::<Bls12>::generate(&mut rng);
            let message = format!(">16 character message {}", i);
            let sig = keypair.sign(&message.as_bytes());
            let cloned_pub = keypair.public.clone();
            assert_eq!(cloned_pub.verify(&message.as_bytes(), &sig), true);
        }
    }
}
