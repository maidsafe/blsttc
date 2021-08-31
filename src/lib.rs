//! A pairing-based threshold cryptosystem for collaborative decryption and signatures.

// Clippy warns that it's dangerous to derive `PartialEq` and explicitly implement `Hash`, but the
// `pairing::bls12_381` types don't implement `Hash`, so we can't derive it.
#![allow(clippy::derive_hash_xor_eq)]
#![warn(missing_docs)]

pub use ff;
pub use group;
pub use pairing;

mod cmp_pairing;
mod into_fr;
mod secret;
mod util;

#[cfg(feature = "codec-support")]
#[macro_use]
mod codec_impl;

pub mod convert;
pub mod error;
pub mod poly;
pub mod serde_impl;

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::vec::Vec;

use ff::Field;
use group::{CurveAffine, CurveProjective, EncodedPoint};
use hex_fmt::HexFmt;
use log::debug;
use pairing::Engine;
use rand::distributions::{Distribution, Standard};
use rand::{rngs::OsRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::cmp_pairing::cmp_projective;
use crate::error::{Error, FromBytesError, FromBytesResult, Result};
use crate::poly::{Commitment, Poly};
use crate::secret::clear_fr;

pub use crate::into_fr::IntoFr;

use convert::{
    fr_from_be_bytes, fr_to_be_bytes, g1_from_be_bytes, g1_to_be_bytes, g2_from_be_bytes,
    g2_to_be_bytes,
};
use util::{derivation_index_into_fr, sha3_256};

use blst::{
    min_pk::{PublicKey as BlstPublicKey, SecretKey as BlstSecretKey, Signature as BlstSignature},
    BLST_ERROR,
};

pub use pairing::bls12_381::{Bls12 as PEngine, Fr, FrRepr, G1Affine, G2Affine, G1, G2};

/// The size of a secret key's representation in bytes.
pub const SK_SIZE: usize = 32;

/// The size of a key's representation in bytes.
pub const PK_SIZE: usize = 48;

/// The size of a signature's representation in bytes.
pub const SIG_SIZE: usize = 96;

/// The domain separator tag
pub const DST: &[u8; 43] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// A public key.
#[derive(Deserialize, Serialize, Copy, Clone, PartialEq, Eq)]
pub struct PublicKey(#[serde(with = "serde_impl::projective")] G1);

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uncomp = self.0.into_affine().into_uncompressed();
        write!(f, "PublicKey({:0.10})", HexFmt(uncomp))
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_projective(&self.0, &other.0)
    }
}

impl PublicKey {
    /// Returns `true` if the signature matches the element of `G2`.
    pub fn verify_g2<H: Into<G2Affine>>(&self, sig: &Signature, hash: H) -> bool {
        PEngine::pairing(self.0, hash) == PEngine::pairing(G1Affine::one(), sig.0)
    }

    /// Returns `true` if the signature matches the message.
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &Signature, msg: M) -> bool {
        // TC
        //self.verify_g2(sig, hash_g2(msg))
        // BLST
        let blst_sig = BlstSignature::from_bytes(&sig.to_bytes()).unwrap();
        let blst_pk = BlstPublicKey::from_bytes(&self.to_bytes()).unwrap();
        blst_sig.verify(false, msg.as_ref(), DST, &[], &blst_pk, false) == BLST_ERROR::BLST_SUCCESS
        // DISABLED
        //true
    }

    /// Encrypts the message using the OS random number generator.
    ///
    /// Uses the `OsRng` by default. To pass in a custom random number generator, use
    /// `encrypt_with_rng()`.
    pub fn encrypt<M: AsRef<[u8]>>(&self, msg: M) -> Ciphertext {
        self.encrypt_with_rng(&mut OsRng, msg)
    }

    /// Encrypts the message.
    pub fn encrypt_with_rng<R: RngCore, M: AsRef<[u8]>>(&self, rng: &mut R, msg: M) -> Ciphertext {
        let r: Fr = Fr::random(rng);
        let u = G1Affine::one().mul(r);
        let v: Vec<u8> = {
            let g = self.0.into_affine().mul(r);
            xor_with_hash(g, msg.as_ref())
        };
        let w = hash_g1_g2(u, &v).into_affine().mul(r);
        Ciphertext(u, v, w)
    }

    /// Derives a child public key for a given index.
    pub fn derive_child(&self, index: &[u8]) -> Self {
        let index_fr = derivation_index_into_fr(index);
        let mut child_g1 = self.0;
        child_g1.mul_assign(index_fr);
        PublicKey(child_g1)
    }

    /// Returns the key with the given representation, if valid.
    pub fn from_bytes(bytes: [u8; PK_SIZE]) -> FromBytesResult<Self> {
        let g1 = g1_from_be_bytes(bytes)?;
        Ok(PublicKey(g1))
    }

    /// Returns a byte string representation of the public key.
    pub fn to_bytes(self) -> [u8; PK_SIZE] {
        g1_to_be_bytes(self.0)
    }
}

/// A public key share.
#[cfg_attr(feature = "codec-support", derive(codec::Encode, codec::Decode))]
#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct PublicKeyShare(PublicKey);

impl fmt::Debug for PublicKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uncomp = (self.0).0.into_affine().into_uncompressed();
        write!(f, "PublicKeyShare({:0.10})", HexFmt(uncomp))
    }
}

impl PublicKeyShare {
    /// Returns `true` if the signature matches the element of `G2`.
    pub fn verify_g2<H: Into<G2Affine>>(&self, sig: &SignatureShare, hash: H) -> bool {
        self.0.verify_g2(&sig.0, hash)
    }

    /// Returns `true` if the signature matches the message.
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &SignatureShare, msg: M) -> bool {
        // TC
        //self.verify_g2(sig, hash_g2(msg))
        // BLST
        let blst_sig = BlstSignature::from_bytes(&sig.to_bytes()).unwrap();
        let blst_pk = BlstPublicKey::from_bytes(&self.to_bytes()).unwrap();
        blst_sig.verify(false, msg.as_ref(), DST, &[], &blst_pk, false) == BLST_ERROR::BLST_SUCCESS
        // DISABLED
        //true
    }

    /// Returns `true` if the decryption share matches the ciphertext.
    pub fn verify_decryption_share(&self, share: &DecryptionShare, ct: &Ciphertext) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *ct;
        let hash = hash_g1_g2(*u, v);
        PEngine::pairing(share.0, hash) == PEngine::pairing((self.0).0, *w)
    }

    /// Derives a child public key share for a given index.
    pub fn derive_child(&self, index: &[u8]) -> Self {
        PublicKeyShare(self.0.derive_child(index))
    }

    /// Returns the key share with the given representation, if valid.
    pub fn from_bytes(bytes: [u8; PK_SIZE]) -> FromBytesResult<Self> {
        Ok(PublicKeyShare(PublicKey::from_bytes(bytes)?))
    }

    /// Returns a byte string representation of the public key share.
    pub fn to_bytes(self) -> [u8; PK_SIZE] {
        self.0.to_bytes()
    }
}

/// A signature.
// Note: Random signatures can be generated for testing.
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Signature(#[serde(with = "serde_impl::projective")] G2);

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_projective(&self.0, &other.0)
    }
}

impl Distribution<Signature> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Signature {
        Signature(G2::random(rng))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uncomp = self.0.into_affine().into_uncompressed();
        write!(f, "Signature({:0.10})", HexFmt(uncomp))
    }
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl Signature {
    /// Returns `true` if the signature contains an odd number of ones.
    pub fn parity(&self) -> bool {
        let uncomp = self.0.into_affine().into_uncompressed();
        let xor_bytes: u8 = uncomp.as_ref().iter().fold(0, |result, byte| result ^ byte);
        let parity = 0 != xor_bytes.count_ones() % 2;
        debug!("Signature: {:0.10}, parity: {}", HexFmt(uncomp), parity);
        parity
    }

    /// Returns the signature with the given representation, if valid.
    pub fn from_bytes(bytes: [u8; SIG_SIZE]) -> FromBytesResult<Self> {
        let g2 = g2_from_be_bytes(bytes)?;
        Ok(Signature(g2))
    }

    /// Returns a byte string representation of the signature.
    pub fn to_bytes(&self) -> [u8; SIG_SIZE] {
        g2_to_be_bytes(self.0)
    }
}

/// A signature share.
// Note: Random signature shares can be generated for testing.
#[cfg_attr(feature = "codec-support", derive(codec::Encode, codec::Decode))]
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct SignatureShare(pub Signature);

impl Distribution<SignatureShare> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SignatureShare {
        SignatureShare(rng.gen())
    }
}

impl fmt::Debug for SignatureShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uncomp = (self.0).0.into_affine().into_uncompressed();
        write!(f, "SignatureShare({:0.10})", HexFmt(uncomp))
    }
}

impl SignatureShare {
    /// Returns the signature share with the given representation, if valid.
    pub fn from_bytes(bytes: [u8; SIG_SIZE]) -> FromBytesResult<Self> {
        Ok(SignatureShare(Signature::from_bytes(bytes)?))
    }

    /// Returns a byte string representation of the signature share.
    pub fn to_bytes(&self) -> [u8; SIG_SIZE] {
        self.0.to_bytes()
    }
}

/// A secret key; wraps a single prime field element. The field element is
/// heap allocated to avoid any stack copying that result when passing
/// `SecretKey`s between stack frames.
///
/// # Serde integration
/// `SecretKey` implements `Deserialize` but not `Serialize` to avoid accidental
/// serialization in insecure contexts. To enable both use the `::serde_impl::SerdeSecret`
/// wrapper which implements both `Deserialize` and `Serialize`.
#[derive(PartialEq, Eq, Clone)]
pub struct SecretKey(Fr);

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        clear_fr(&mut self.0)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Creates a `SecretKey` containing the zero prime field element.
impl Default for SecretKey {
    fn default() -> Self {
        let mut fr = Fr::zero();
        SecretKey::from_mut(&mut fr)
    }
}

impl Distribution<SecretKey> for Standard {
    /// Creates a new random instance of `SecretKey`. If you do not need to specify your own RNG,
    /// you should use the [`SecretKey::random()`](struct.SecretKey.html#method.random) constructor,
    /// which uses [`rand::thread_rng()`](https://docs.rs/rand/0.7.2/rand/fn.thread_rng.html)
    /// internally as its RNG.
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SecretKey {
        SecretKey(Fr::random(rng))
    }
}

/// A debug statement where the secret prime field element is redacted.
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKey").field(&DebugDots).finish()
    }
}

impl SecretKey {
    /// Creates a new `SecretKey` from a mutable reference to a field element. This constructor
    /// takes a reference to avoid any unnecessary stack copying/moving of secrets (i.e. the field
    /// element). The field element is copied bytewise onto the heap, the resulting `Box` is
    /// stored in the returned `SecretKey`.
    ///
    /// *WARNING* this constructor will overwrite the referenced `Fr` element with zeros after it
    /// has been copied onto the heap.
    pub fn from_mut(fr: &mut Fr) -> Self {
        let sk = SecretKey(*fr);
        clear_fr(fr);
        sk
    }

    /// Creates a new random instance of `SecretKey`.
    ///
    /// If you want to use/define your own random number generator, you should use the constructor:
    /// [`SecretKey::sample()`](struct.SecretKey.html#impl-Distribution<SecretKey>). If you do not
    /// need to specify your own RNG, you should use the
    /// [`SecretKey::random()`](struct.SecretKey.html#method.random) constructor, which uses
    /// [`rand::thread_rng()`](https://docs.rs/rand/0.7.2/rand/fn.thread_rng.html) internally as its
    /// RNG.
    pub fn random() -> Self {
        rand::random()
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(G1Affine::one().mul(self.0))
    }

    /// Signs the given element of `G2`.
    pub fn sign_g2<H: Into<G2Affine>>(&self, hash: H) -> Signature {
        Signature(hash.into().mul(self.0))
    }

    /// Signs the given message.
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> Signature {
        // TC
        //self.sign_g2(hash_g2(msg))
        // BLST
        let blst_sk = BlstSecretKey::from_bytes(&self.to_bytes()).unwrap();
        let blst_sig = blst_sk.sign(msg.as_ref(), DST, &[]);
        Signature::from_bytes(blst_sig.to_bytes()).unwrap()
        // DISABLED
        //Signature::from_bytes([
        //    174, 110, 104, 53, 218, 40, 126, 73, 178, 216, 213, 13, 22, 20,
        //    166, 46, 201, 163, 42, 74, 181, 235, 176, 22, 48, 117, 85, 234,
        //    236, 215, 64, 46, 166, 100, 98, 63, 112, 27, 79, 224, 189, 80,
        //    214, 39, 45, 233, 94, 141, 1, 14, 227, 20, 128, 126, 235, 99, 222,
        //    6, 89, 192, 186, 12, 237, 209, 190, 36, 2, 126, 48, 168, 57, 240,
        //    25, 169, 238, 190, 77, 132, 88, 41, 192, 45, 221, 113, 162, 17,
        //    127, 230, 122, 254, 54, 247, 58, 169, 160, 151
        //]).unwrap()
    }

    /// Converts the secret key to big endian bytes
    pub fn to_bytes(&self) -> [u8; SK_SIZE] {
        fr_to_be_bytes(self.0)
    }

    /// Deserialize from big endian bytes
    pub fn from_bytes(bytes: [u8; SK_SIZE]) -> FromBytesResult<Self> {
        let mut fr = fr_from_be_bytes(bytes)?;
        Ok(SecretKey::from_mut(&mut fr))
    }

    /// Returns the decrypted text, or `None`, if the ciphertext isn't valid.
    pub fn decrypt(&self, ct: &Ciphertext) -> Option<Vec<u8>> {
        if !ct.verify() {
            return None;
        }
        let Ciphertext(ref u, ref v, _) = *ct;
        let g = u.into_affine().mul(self.0);
        Some(xor_with_hash(g, v))
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field element.
    pub fn reveal(&self) -> String {
        format!("SecretKey({:?})", self.0)
    }

    /// Derives a child secret key for a given index.
    pub fn derive_child(&self, index: &[u8]) -> Self {
        let mut index_fr = derivation_index_into_fr(index);
        index_fr.mul_assign(&self.0);
        SecretKey(index_fr)
    }
}

/// A secret key share.
///
/// # Serde integration
/// `SecretKeyShare` implements `Deserialize` but not `Serialize` to avoid accidental
/// serialization in insecure contexts. To enable both use the `::serde_impl::SerdeSecret`
/// wrapper which implements both `Deserialize` and `Serialize`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretKeyShare(SecretKey);

/// Can be used to create a new random instance of `SecretKeyShare`. This is only useful for testing
/// purposes as such a key has not been derived from a `SecretKeySet`.
impl Distribution<SecretKeyShare> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SecretKeyShare {
        SecretKeyShare(rng.gen())
    }
}

impl fmt::Debug for SecretKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKeyShare").field(&DebugDots).finish()
    }
}

impl SecretKeyShare {
    /// Creates a new `SecretKeyShare` from a mutable reference to a field element. This
    /// constructor takes a reference to avoid any unnecessary stack copying/moving of secrets
    /// field elements. The field element will be copied bytewise onto the heap, the resulting
    /// `Box` is stored in the `SecretKey` which is then wrapped in a `SecretKeyShare`.
    ///
    /// *WARNING* this constructor will overwrite the pointed to `Fr` element with zeros once it
    /// has been copied into a new `SecretKeyShare`.
    pub fn from_mut(fr: &mut Fr) -> Self {
        SecretKeyShare(SecretKey::from_mut(fr))
    }

    /// Returns the matching public key share.
    pub fn public_key_share(&self) -> PublicKeyShare {
        PublicKeyShare(self.0.public_key())
    }

    /// Signs the given element of `G2`.
    pub fn sign_g2<H: Into<G2Affine>>(&self, hash: H) -> SignatureShare {
        SignatureShare(self.0.sign_g2(hash))
    }

    /// Signs the given message.
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> SignatureShare {
        SignatureShare(self.0.sign(msg))
    }

    /// Returns a decryption share, or `None`, if the ciphertext isn't valid.
    pub fn decrypt_share(&self, ct: &Ciphertext) -> Option<DecryptionShare> {
        if !ct.verify() {
            return None;
        }
        Some(self.decrypt_share_no_verify(ct))
    }

    /// Returns a decryption share, without validating the ciphertext.
    pub fn decrypt_share_no_verify(&self, ct: &Ciphertext) -> DecryptionShare {
        DecryptionShare(ct.0.into_affine().mul((self.0).0))
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field element.
    pub fn reveal(&self) -> String {
        format!("SecretKeyShare({:?})", (self.0).0)
    }

    /// Derives a child secret key share for a given index.
    pub fn derive_child(&self, index: &[u8]) -> Self {
        SecretKeyShare(self.0.derive_child(index))
    }

    /// Serializes to big endian bytes
    pub fn to_bytes(&self) -> [u8; SK_SIZE] {
        self.0.to_bytes()
    }

    /// Deserializes from big endian bytes
    pub fn from_bytes(bytes: [u8; SK_SIZE]) -> FromBytesResult<Self> {
        Ok(SecretKeyShare(SecretKey::from_bytes(bytes)?))
    }
}

/// An encrypted message.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext(
    #[serde(with = "serde_impl::projective")] G1,
    Vec<u8>,
    #[serde(with = "serde_impl::projective")] G2,
);

impl Hash for Ciphertext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let Ciphertext(ref u, ref v, ref w) = *self;
        u.into_affine().into_compressed().as_ref().hash(state);
        v.hash(state);
        w.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl PartialOrd for Ciphertext {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ciphertext {
    fn cmp(&self, other: &Self) -> Ordering {
        let Ciphertext(ref u0, ref v0, ref w0) = self;
        let Ciphertext(ref u1, ref v1, ref w1) = other;
        cmp_projective(u0, u1)
            .then(v0.cmp(v1))
            .then(cmp_projective(w0, w1))
    }
}

impl Ciphertext {
    /// Returns `true` if this is a valid ciphertext. This check is necessary to prevent
    /// chosen-ciphertext attacks.
    pub fn verify(&self) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *self;
        let hash = hash_g1_g2(*u, v);
        PEngine::pairing(G1Affine::one(), *w) == PEngine::pairing(*u, hash)
    }

    /// Returns byte representation of Ciphertext
    pub fn to_bytes(&self) -> Vec<u8> {
        let Ciphertext(ref u, ref v, ref w) = *self;
        let mut result: Vec<u8> = Default::default();
        result.extend(u.into_affine().into_compressed().as_ref());
        result.extend(w.into_affine().into_compressed().as_ref());
        result.extend(v);
        result
    }

    /// Returns the Ciphertext with the given representation, if valid.
    pub fn from_bytes(bytes: &[u8]) -> FromBytesResult<Self> {
        if bytes.len() < PK_SIZE + SIG_SIZE + 1 {
            return Err(FromBytesError::Invalid);
        }

        let mut u_compressed: <G1Affine as CurveAffine>::Compressed = EncodedPoint::empty();
        u_compressed.as_mut().copy_from_slice(&bytes[0..PK_SIZE]);

        let mut w_compressed: <G2Affine as CurveAffine>::Compressed = EncodedPoint::empty();
        w_compressed
            .as_mut()
            .copy_from_slice(&bytes[PK_SIZE..PK_SIZE + SIG_SIZE]);

        let v: Vec<u8> = (&bytes[PK_SIZE + SIG_SIZE..]).to_vec();

        Ok(Self(
            u_compressed
                .into_affine()
                .ok()
                .ok_or(FromBytesError::Invalid)?
                .into_projective(),
            v,
            w_compressed
                .into_affine()
                .ok()
                .ok_or(FromBytesError::Invalid)?
                .into_projective(),
        ))
    }
}

/// A decryption share. A threshold of decryption shares can be used to decrypt a message.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DecryptionShare(#[serde(with = "serde_impl::projective")] G1);

impl Distribution<DecryptionShare> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> DecryptionShare {
        DecryptionShare(G1::random(rng))
    }
}

impl Hash for DecryptionShare {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl fmt::Debug for DecryptionShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DecryptionShare").field(&DebugDots).finish()
    }
}

impl DecryptionShare {
    /// Deserializes the share from big endian bytes
    pub fn from_bytes(bytes: [u8; PK_SIZE]) -> FromBytesResult<Self> {
        let g1 = g1_from_be_bytes(bytes)?;
        Ok(DecryptionShare(g1))
    }

    /// Serializes the share as big endian bytes
    pub fn to_bytes(&self) -> [u8; PK_SIZE] {
        g1_to_be_bytes(self.0)
    }
}

/// A public key and an associated set of public key shares.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct PublicKeySet {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    commit: Commitment,
}

impl Hash for PublicKeySet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.commit.hash(state);
    }
}

impl fmt::Debug for PublicKeySet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PublicKeySet")
            .field("public_key", &self.public_key())
            .field("threshold", &self.threshold())
            .finish()
    }
}

impl From<Commitment> for PublicKeySet {
    fn from(commit: Commitment) -> PublicKeySet {
        PublicKeySet { commit }
    }
}

impl PublicKeySet {
    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.commit.degree()
    }

    /// Returns the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.commit.coeff[0])
    }

    /// Returns the `i`-th public key share.
    pub fn public_key_share<T: IntoFr>(&self, i: T) -> PublicKeyShare {
        let value = self.commit.evaluate(into_fr_plus_1(i));
        PublicKeyShare(PublicKey(value))
    }

    /// Combines the shares into a signature that can be verified with the main public key.
    ///
    /// The validity of the shares is not checked: If one of them is invalid, the resulting
    /// signature also is. Only returns an error if there is a duplicate index or too few shares.
    ///
    /// Validity of signature shares should be checked beforehand, or validity of the result
    /// afterwards:
    ///
    /// ```
    /// # extern crate rand;
    /// #
    /// # use std::collections::BTreeMap;
    /// # use blsttc::SecretKeySet;
    /// #
    /// let sk_set = SecretKeySet::random(3, &mut rand::thread_rng());
    /// let sk_shares: Vec<_> = (0..6).map(|i| sk_set.secret_key_share(i)).collect();
    /// let pk_set = sk_set.public_keys();
    /// let msg = "Happy birthday! If this is signed, at least four people remembered!";
    ///
    /// // Create four signature shares for the message.
    /// let sig_shares: BTreeMap<_, _> = (0..4).map(|i| (i, sk_shares[i].sign(msg))).collect();
    ///
    /// // Validate the signature shares.
    /// for (i, sig_share) in &sig_shares {
    ///     assert!(pk_set.public_key_share(*i).verify(sig_share, msg));
    /// }
    ///
    /// // Combine them to produce the main signature.
    /// let sig = pk_set.combine_signatures(&sig_shares).expect("not enough shares");
    ///
    /// // Validate the main signature. If the shares were valid, this can't fail.
    /// assert!(pk_set.public_key().verify(&sig, msg));
    /// ```
    pub fn combine_signatures<'a, T, I>(&self, shares: I) -> Result<Signature>
    where
        I: IntoIterator<Item = (T, &'a SignatureShare)>,
        T: IntoFr,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, &(share.0).0));
        Ok(Signature(interpolate(self.commit.degree(), samples)?))
    }

    /// Combines the shares to decrypt the ciphertext.
    pub fn decrypt<'a, T, I>(&self, shares: I, ct: &Ciphertext) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = (T, &'a DecryptionShare)>,
        T: IntoFr,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, &share.0));
        let g = interpolate(self.commit.degree(), samples)?;
        Ok(xor_with_hash(g, &ct.1))
    }

    /// Derives a child public key set for a given index.
    pub fn derive_child(&self, index: &[u8]) -> Self {
        let index_fr = derivation_index_into_fr(index);
        let child_coeffs: Vec<G1> = self
            .commit
            .coeff
            .iter()
            .map(|coeff| {
                let mut child_coeff = *coeff;
                child_coeff.mul_assign(index_fr);
                child_coeff
            })
            .collect();
        PublicKeySet::from(Commitment::from(child_coeffs))
    }

    /// Serializes to big endian bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.commit.to_bytes()
    }

    /// Deserializes from big endian bytes
    pub fn from_bytes(bytes: Vec<u8>) -> FromBytesResult<Self> {
        let commit = Commitment::from_bytes(bytes)?;
        Ok(PublicKeySet { commit })
    }
}

/// A secret key and an associated set of secret key shares.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKeySet {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    poly: Poly,
}

impl From<Poly> for SecretKeySet {
    fn from(poly: Poly) -> SecretKeySet {
        SecretKeySet { poly }
    }
}

impl SecretKeySet {
    /// Creates a set of secret key shares, where any `threshold + 1` of them can collaboratively
    /// sign and decrypt. This constructor is identical to the `SecretKeySet::try_random()` in every
    /// way except that this constructor panics if the other returns an error.
    ///
    /// # Panic
    ///
    /// Panics if the `threshold` is too large for the coefficients to fit into a `Vec`.
    pub fn random<R: Rng>(threshold: usize, rng: &mut R) -> Self {
        SecretKeySet::try_random(threshold, rng)
            .unwrap_or_else(|e| panic!("Failed to create random `SecretKeySet`: {}", e))
    }

    /// Creates a set of secret key shares, where any `threshold + 1` of them can collaboratively
    /// sign and decrypt. This constructor is identical to the `SecretKeySet::random()` in every
    /// way except that this constructor returns an `Err` where the `random` would panic.
    pub fn try_random<R: Rng>(threshold: usize, rng: &mut R) -> Result<Self> {
        Poly::try_random(threshold, rng).map(SecretKeySet::from)
    }

    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.poly.degree()
    }

    /// Returns the `i`-th secret key share.
    pub fn secret_key_share<T: IntoFr>(&self, i: T) -> SecretKeyShare {
        let mut fr = self.poly.evaluate(into_fr_plus_1(i));
        SecretKeyShare::from_mut(&mut fr)
    }

    /// Returns the corresponding public key set. That information can be shared publicly.
    pub fn public_keys(&self) -> PublicKeySet {
        PublicKeySet {
            commit: self.poly.commitment(),
        }
    }

    /// Returns a reference to the polynomial
    pub fn poly(&self) -> &Poly {
        &self.poly
    }

    /// Returns the secret master key.
    pub fn secret_key(&self) -> SecretKey {
        let mut fr = self.poly.evaluate(0);
        SecretKey::from_mut(&mut fr)
    }

    /// Derives a child secret key set for a given index.
    pub fn derive_child(&self, index: &[u8]) -> Self {
        // Equivalent to self.poly.clone() * index_fr;
        // The code here follows the same structure as in PublicKeySet for
        // similarity / symmetry / aesthetics, since Commitment can't be
        // multiplied by Fr the same way Poly can.
        let index_fr = derivation_index_into_fr(index);
        let child_coeffs: Vec<Fr> = self
            .poly
            .coeff
            .iter()
            .map(|coeff| {
                let mut child_coeff = *coeff;
                child_coeff.mul_assign(&index_fr);
                child_coeff
            })
            .collect();
        SecretKeySet::from(Poly::from(child_coeffs))
    }

    /// Serializes to big endian bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.poly.to_bytes()
    }

    /// Deserializes from big endian bytes
    pub fn from_bytes(bytes: Vec<u8>) -> FromBytesResult<Self> {
        let poly = Poly::from_bytes(bytes)?;
        Ok(SecretKeySet { poly })
    }
}

/// Returns a hash of the given message in `G2`.
pub fn hash_g2<M: AsRef<[u8]>>(msg: M) -> G2 {
    let digest = sha3_256(msg.as_ref());
    G2::random(&mut ChaChaRng::from_seed(digest))
}

/// Returns a hash of the group element and message, in the second group.
fn hash_g1_g2<M: AsRef<[u8]>>(g1: G1, msg: M) -> G2 {
    // If the message is large, hash it, otherwise copy it.
    // TODO: Benchmark and optimize the threshold.
    let mut msg = if msg.as_ref().len() > 64 {
        sha3_256(msg.as_ref()).to_vec()
    } else {
        msg.as_ref().to_vec()
    };
    msg.extend(g1.into_affine().into_compressed().as_ref());
    hash_g2(&msg)
}

/// Returns the bitwise xor of `bytes` with a sequence of pseudorandom bytes determined by `g1`.
fn xor_with_hash(g1: G1, bytes: &[u8]) -> Vec<u8> {
    let digest = sha3_256(g1.into_affine().into_compressed().as_ref());
    let rng = ChaChaRng::from_seed(digest);
    let xor = |(a, b): (u8, &u8)| a ^ b;
    rng.sample_iter(&Standard).zip(bytes).map(xor).collect()
}

/// Given a list of `t + 1` samples `(i - 1, f(i) * g)` for a polynomial `f` of degree `t`, and a
/// group generator `g`, returns `f(0) * g`.
fn interpolate<C, B, T, I>(t: usize, items: I) -> Result<C>
where
    C: CurveProjective<Scalar = Fr>,
    I: IntoIterator<Item = (T, B)>,
    T: IntoFr,
    B: Borrow<C>,
{
    let samples: Vec<_> = items
        .into_iter()
        .take(t + 1)
        .map(|(i, sample)| (into_fr_plus_1(i), sample))
        .collect();
    if samples.len() <= t {
        return Err(Error::NotEnoughShares);
    }

    if t == 0 {
        return Ok(*samples[0].1.borrow());
    }

    // Compute the products `x_prod[i]` of all but the `i`-th entry.
    let mut x_prod: Vec<C::Scalar> = Vec::with_capacity(t);
    let mut tmp = C::Scalar::one();
    x_prod.push(tmp);
    for (x, _) in samples.iter().take(t) {
        tmp.mul_assign(x);
        x_prod.push(tmp);
    }
    tmp = C::Scalar::one();
    for (i, (x, _)) in samples[1..].iter().enumerate().rev() {
        tmp.mul_assign(x);
        x_prod[i].mul_assign(&tmp);
    }

    let mut result = C::zero();
    for (mut l0, (x, sample)) in x_prod.into_iter().zip(&samples) {
        // Compute the value at 0 of the Lagrange polynomial that is `0` at the other data
        // points but `1` at `x`.
        let mut denom = C::Scalar::one();
        for (x0, _) in samples.iter().filter(|(x0, _)| x0 != x) {
            let mut diff = *x0;
            diff.sub_assign(x);
            denom.mul_assign(&diff);
        }
        l0.mul_assign(&denom.inverse().ok_or(Error::DuplicateEntry)?);
        result.add_assign(&sample.borrow().into_affine().mul(l0));
    }
    Ok(result)
}

fn into_fr_plus_1<I: IntoFr>(x: I) -> Fr {
    let mut result = Fr::one();
    result.add_assign(&x.into_fr());
    result
}

/// Type that implements `Debug` printing three dots. This can be used to hide the contents of a
/// field in a `Debug` implementation.
struct DebugDots;

impl fmt::Debug for DebugDots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use rand::{self, distributions::Standard, random, Rng};

    #[test]
    fn test_interpolate() {
        let mut rng = rand::thread_rng();
        for deg in 0..5 {
            println!("deg = {}", deg);
            let comm = Poly::random(deg, &mut rng).commitment();
            let mut values = Vec::new();
            let mut x = 0;
            for _ in 0..=deg {
                x += rng.gen_range(1, 5);
                values.push((x - 1, comm.evaluate(x)));
            }
            let actual = interpolate(deg, values).expect("wrong number of values");
            assert_eq!(comm.evaluate(0), actual);
        }
    }

    #[test]
    fn test_simple_sig() {
        let sk0 = SecretKey::random();
        let sk1 = SecretKey::random();
        let pk0 = sk0.public_key();
        let msg0 = b"Real news";
        let msg1 = b"Fake news";
        assert!(pk0.verify(&sk0.sign(msg0), msg0));
        assert!(!pk0.verify(&sk1.sign(msg0), msg0)); // Wrong key.
        assert!(!pk0.verify(&sk0.sign(msg1), msg0)); // Wrong message.
    }

    #[test]
    fn test_threshold_sig() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let pk_master = pk_set.public_key();

        // Make sure the keys are different, and the first coefficient is the main key.
        assert_ne!(pk_master, pk_set.public_key_share(0).0);
        assert_ne!(pk_master, pk_set.public_key_share(1).0);
        assert_ne!(pk_master, pk_set.public_key_share(2).0);

        // Make sure we don't hand out the main secret key to anyone.
        let sk_master = sk_set.secret_key();
        let sk_share_0 = sk_set.secret_key_share(0).0;
        let sk_share_1 = sk_set.secret_key_share(1).0;
        let sk_share_2 = sk_set.secret_key_share(2).0;
        assert_ne!(sk_master, sk_share_0);
        assert_ne!(sk_master, sk_share_1);
        assert_ne!(sk_master, sk_share_2);

        let msg = "Totally real news";

        // The threshold is 3, so 4 signature shares will suffice to recreate the share.
        let sigs: BTreeMap<_, _> = [5, 8, 7, 10]
            .iter()
            .map(|&i| {
                let sig = sk_set.secret_key_share(i).sign(msg);
                (i, sig)
            })
            .collect();

        // Each of the shares is a valid signature matching its public key share.
        for (i, sig) in &sigs {
            assert!(pk_set.public_key_share(*i).verify(sig, msg));
        }

        // Combined, they produce a signature matching the main public key.
        let sig = pk_set.combine_signatures(&sigs).expect("signatures match");
        assert!(pk_set.public_key().verify(&sig, msg));

        // A different set of signatories produces the same signature.
        let sigs2: BTreeMap<_, _> = [42, 43, 44, 45]
            .iter()
            .map(|&i| {
                let sig = sk_set.secret_key_share(i).sign(msg);
                (i, sig)
            })
            .collect();
        let sig2 = pk_set.combine_signatures(&sigs2).expect("signatures match");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_simple_enc() {
        let sk_bob: SecretKey = random();
        let sk_eve: SecretKey = random();
        let pk_bob = sk_bob.public_key();
        let msg = b"Muffins in the canteen today! Don't tell Eve!";
        let ciphertext = pk_bob.encrypt(&msg[..]);
        assert!(ciphertext.verify());

        // Bob can decrypt the message.
        let decrypted = sk_bob.decrypt(&ciphertext).expect("invalid ciphertext");
        assert_eq!(msg[..], decrypted[..]);

        // Eve can't.
        let decrypted_eve = sk_eve.decrypt(&ciphertext).expect("invalid ciphertext");
        assert_ne!(msg[..], decrypted_eve[..]);

        // Eve tries to trick Bob into decrypting `msg` xor `v`, but it doesn't validate.
        let Ciphertext(u, v, w) = ciphertext;
        let fake_ciphertext = Ciphertext(u, vec![0; v.len()], w);
        assert!(!fake_ciphertext.verify());
        assert_eq!(None, sk_bob.decrypt(&fake_ciphertext));
    }

    #[test]
    fn test_random_extreme_thresholds() {
        let mut rng = rand::thread_rng();
        let sks = SecretKeySet::random(0, &mut rng);
        assert_eq!(0, sks.threshold());
        assert!(SecretKeySet::try_random(usize::max_value(), &mut rng).is_err());
    }

    #[test]
    fn test_threshold_enc() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let msg = b"Totally real news";
        let ciphertext = pk_set.public_key().encrypt(&msg[..]);

        // The threshold is 3, so 4 signature shares will suffice to decrypt.
        let shares: BTreeMap<_, _> = [5, 8, 7, 10]
            .iter()
            .map(|&i| {
                let dec_share = sk_set
                    .secret_key_share(i)
                    .decrypt_share(&ciphertext)
                    .expect("ciphertext is invalid");
                (i, dec_share)
            })
            .collect();

        // Each of the shares is valid matching its public key share.
        for (i, share) in &shares {
            pk_set
                .public_key_share(*i)
                .verify_decryption_share(share, &ciphertext);
        }

        // Combined, they can decrypt the message.
        let decrypted = pk_set
            .decrypt(&shares, &ciphertext)
            .expect("decryption shares match");
        assert_eq!(msg[..], decrypted[..]);
    }

    /// Some basic sanity checks for the `hash_g2` function.
    #[test]
    fn test_hash_g2() {
        let rng = rand::thread_rng();
        let msg: Vec<u8> = rng.sample_iter(&Standard).take(1000).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();

        assert_eq!(hash_g2(&msg), hash_g2(&msg));
        assert_ne!(hash_g2(&msg), hash_g2(&msg_end0));
        assert_ne!(hash_g2(&msg_end0), hash_g2(&msg_end1));
    }

    /// Some basic sanity checks for the `hash_g1_g2` function.
    #[test]
    fn test_hash_g1_g2() {
        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = rng.sample_iter(&Standard).take(1000).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();
        let g0 = G1::random(&mut rng);
        let g1 = G1::random(&mut rng);

        assert_eq!(hash_g1_g2(g0, &msg), hash_g1_g2(g0, &msg));
        assert_ne!(hash_g1_g2(g0, &msg), hash_g1_g2(g0, &msg_end0));
        assert_ne!(hash_g1_g2(g0, &msg_end0), hash_g1_g2(g0, &msg_end1));
        assert_ne!(hash_g1_g2(g0, &msg), hash_g1_g2(g1, &msg));
    }

    /// Some basic sanity checks for the `hash_bytes` function.
    #[test]
    fn test_xor_with_hash() {
        let mut rng = rand::thread_rng();
        let g0 = G1::random(&mut rng);
        let g1 = G1::random(&mut rng);
        let xwh = xor_with_hash;
        assert_eq!(xwh(g0, &[0; 5]), xwh(g0, &[0; 5]));
        assert_ne!(xwh(g0, &[0; 5]), xwh(g1, &[0; 5]));
        assert_eq!(5, xwh(g0, &[0; 5]).len());
        assert_eq!(6, xwh(g0, &[0; 6]).len());
        assert_eq!(20, xwh(g0, &[0; 20]).len());
    }

    #[test]
    fn test_from_to_bytes() {
        let sk: SecretKey = random();
        let sig = sk.sign("Please sign here: ______");
        let pk = sk.public_key();
        let pk2 = PublicKey::from_bytes(pk.to_bytes()).expect("invalid pk representation");
        assert_eq!(pk, pk2);
        let sig2 = Signature::from_bytes(sig.to_bytes()).expect("invalid sig representation");
        assert_eq!(sig, sig2);
        let cipher = sk.public_key().encrypt(b"secret msg");
        let cipher2 =
            Ciphertext::from_bytes(&cipher.to_bytes()).expect("invalid cipher representation");
        assert_eq!(cipher, cipher2);
    }

    #[test]
    fn test_serde() {
        let sk = SecretKey::random();
        let sig = sk.sign("Please sign here: ______");
        let pk = sk.public_key();
        let ser_pk = bincode::serialize(&pk).expect("serialize public key");
        let deser_pk = bincode::deserialize(&ser_pk).expect("deserialize public key");
        assert_eq!(ser_pk.len(), PK_SIZE);
        assert_eq!(pk, deser_pk);
        let ser_sig = bincode::serialize(&sig).expect("serialize signature");
        let deser_sig = bincode::deserialize(&ser_sig).expect("deserialize signature");
        assert_eq!(ser_sig.len(), SIG_SIZE);
        assert_eq!(sig, deser_sig);
    }

    #[cfg(feature = "codec-support")]
    #[test]
    fn test_codec() {
        use codec::{Decode, Encode};
        use rand::distributions::{Distribution, Standard};
        use rand::thread_rng;

        macro_rules! assert_codec {
            ($obj:expr, $type:ty) => {
                let encoded: Vec<u8> = $obj.encode();
                let decoded: $type = <$type>::decode(&mut &encoded[..]).unwrap();
                assert_eq!(decoded, $obj.clone());
            };
        }

        let sk = SecretKey::random();
        let pk = sk.public_key();
        assert_codec!(pk, PublicKey);

        let pk_share = PublicKeyShare(pk);
        assert_codec!(pk_share, PublicKeyShare);

        let sig = sk.sign(b"this is a test");
        assert_codec!(sig, Signature);

        let sig_share = SignatureShare(sig);
        assert_codec!(sig_share, SignatureShare);

        let cipher_text = pk.encrypt(b"cipher text");
        assert_codec!(cipher_text, Ciphertext);

        let dec_share: DecryptionShare = Standard.sample(&mut thread_rng());
        assert_codec!(dec_share, DecryptionShare);

        let sk_set = SecretKeySet::random(3, &mut thread_rng());
        let pk_set = sk_set.public_keys();
        assert_codec!(pk_set, PublicKeySet);
    }

    #[test]
    fn test_size() {
        assert_eq!(<G1Affine as CurveAffine>::Compressed::size(), PK_SIZE);
        assert_eq!(<G2Affine as CurveAffine>::Compressed::size(), SIG_SIZE);
    }

    #[test]
    fn test_zeroize() {
        let zero_sk = SecretKey::from_mut(&mut Fr::zero());

        let mut sk = SecretKey::random();
        assert_ne!(zero_sk, sk);

        sk.zeroize();
        assert_eq!(zero_sk, sk);
    }

    #[test]
    fn test_rng_seed() {
        let sk1 = SecretKey::random();
        let sk2 = SecretKey::random();

        assert_ne!(sk1, sk2);
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);

        let mut rng = ChaChaRng::from_seed(seed);
        let sk3: SecretKey = rng.sample(Standard);

        let mut rng = ChaChaRng::from_seed(seed);
        let sk4: SecretKey = rng.sample(Standard);
        assert_eq!(sk3, sk4);
    }

    #[test]
    fn test_interoperability() {
        // This test only pases if fn sign and fn verify are using the BLST code
        // https://github.com/Chia-Network/bls-signatures/blob/ee71adc0efeae3a7487cf0662b7bee3825752a29/src/test.cpp#L249-L260
        let skbytes = [
            74, 53, 59, 227, 218, 192, 145, 160, 167, 230, 64, 98, 3, 114, 245, 225, 226, 228, 64,
            23, 23, 193, 231, 156, 172, 111, 251, 168, 246, 144, 86, 4,
        ];
        let pkbytes = [
            133, 105, 95, 203, 192, 108, 196, 196, 201, 69, 31, 77, 206, 33, 203, 248, 222, 62, 90,
            19, 191, 72, 244, 76, 219, 177, 142, 32, 56, 186, 123, 139, 177, 99, 45, 121, 17, 239,
            30, 46, 8, 116, 155, 221, 191, 22, 83, 82,
        ];
        let msgbytes = [7, 8, 9];
        let sigbytes = [
            184, 250, 166, 214, 163, 136, 28, 159, 219, 173, 128, 59, 23, 13, 112, 202, 92, 191,
            30, 107, 165, 165, 134, 38, 45, 243, 104, 199, 90, 205, 29, 31, 250, 58, 182, 238, 33,
            199, 31, 132, 68, 148, 101, 152, 120, 245, 235, 35, 12, 149, 141, 213, 118, 176, 139,
            133, 100, 170, 210, 238, 9, 146, 232, 90, 30, 86, 95, 41, 156, 213, 58, 40, 93, 231,
            41, 147, 127, 112, 220, 23, 106, 31, 1, 67, 33, 41, 187, 43, 148, 211, 213, 3, 31, 128,
            101, 161,
        ];
        // no SecretKey::from_bytes method, so use bincode which requires
        // little endian bytes.
        let mut leskbytes = skbytes;
        leskbytes.reverse();
        let sk: SecretKey = bincode::deserialize(&leskbytes).unwrap();
        let pk = sk.public_key();
        // secret key gives same public key
        assert_eq!(pkbytes, pk.to_bytes());
        // signature matches test vector
        let sig = sk.sign(&msgbytes);
        assert_eq!(sigbytes, sig.to_bytes());
        // signature can be verified
        let is_valid = pk.verify(&sig, msgbytes);
        assert!(is_valid);
    }

    #[test]
    fn test_sk_to_from_bytes() {
        use crate::serde_impl::SerdeSecret;
        let sk = SecretKey::random();
        // bincode is little endian, so must reverse to get big endian
        let mut bincode_bytes = bincode::serialize(&SerdeSecret(&sk)).unwrap();
        bincode_bytes.reverse();
        // sk.to_bytes() is big endian
        let sk_be_bytes = sk.to_bytes();
        assert_eq!(bincode_bytes, sk_be_bytes);
        // from bytes gives original secret key
        let restored_sk = SecretKey::from_bytes(sk_be_bytes).expect("invalid sk bytes");
        assert_eq!(sk, restored_sk);
    }

    #[test]
    fn vectors_sk_to_from_bytes() {
        // from https://github.com/Chia-Network/bls-signatures/blob/ee71adc0efeae3a7487cf0662b7bee3825752a29/src/test.cpp#L249
        let sk_hex = "4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604";
        let pk_hex = "85695fcbc06cc4c4c9451f4dce21cbf8de3e5a13bf48f44cdbb18e2038ba7b8bb1632d7911ef1e2e08749bddbf165352";
        let sk_vec = hex::decode(sk_hex).unwrap();
        let mut sk_bytes = [0u8; SK_SIZE];
        sk_bytes[..SK_SIZE].clone_from_slice(&sk_vec[..SK_SIZE]);
        let sk = SecretKey::from_bytes(sk_bytes).expect("invalid sk bytes");
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_to_hex = &format!("{}", HexFmt(&pk_bytes));
        assert_eq!(pk_to_hex, pk_hex);
    }

    #[test]
    fn test_public_key_set_to_from_bytes_distinctive_properties() {
        let threshold = 3;
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(threshold, &mut rng);
        let pk_set = sk_set.public_keys();
        // length is fixed to (threshold + 1) * 48
        let pk_set_bytes = pk_set.to_bytes();
        assert_eq!(pk_set_bytes.len(), (threshold + 1) * PK_SIZE);
        // the first bytes of the public key set match the public key
        let pk = pk_set.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_bytes_size = pk_bytes.len();
        for i in 0..pk_bytes_size {
            assert_eq!(pk_bytes[i], pk_set_bytes[i]);
        }
        // from bytes gives original pk set
        let restored_pk_set =
            PublicKeySet::from_bytes(pk_set_bytes).expect("invalid public key set bytes");
        assert_eq!(pk_set, restored_pk_set);
    }

    #[test]
    fn test_public_key_set_to_from_bytes_threshold_0() {
        // for threshold 0 the public key set matches the public key and all
        // public key shares
        let threshold = 0;
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(threshold, &mut rng);
        let pk_set = sk_set.public_keys();
        let pk_set_bytes = pk_set.to_bytes();
        let pk = pk_set.public_key();
        let pk_bytes = pk.to_bytes();
        assert_eq!(pk_set_bytes, pk_bytes);
        let pk_share_0 = pk_set.public_key_share(0);
        let pk_share_0_bytes = pk_share_0.to_bytes();
        assert_eq!(pk_set_bytes, pk_share_0_bytes);
        let pk_share_1 = pk_set.public_key_share(1);
        let pk_share_1_bytes = pk_share_1.to_bytes();
        assert_eq!(pk_set_bytes, pk_share_1_bytes);
    }

    #[test]
    fn vectors_public_key_set_to_from_bytes() {
        let vectors = vec![
            // Plain old Public Key Set
            vec![
                // public key set
                "b89f8983d73b6ef75f07f90bc5a58d501b9204f9f304fc9354a66271944b25460845b22d3759c2c8889be552ae23617096b5bfcf90273c61ad102f97c66155de2d9eee3b803e83118095d8b0955f177b105371481e8d9b18d8f610a05b94c1cf",
                // public key
                "b89f8983d73b6ef75f07f90bc5a58d501b9204f9f304fc9354a66271944b25460845b22d3759c2c8889be552ae236170",
                // public key share 0
                "a0f7640853a86e68ef7ac705b6f5bdd15bb4656dbe9578b24b2cceb1ee8576646de140a417eb687e7dbe1a1bfff4f5cd",
                // public key share 1
                "8c2e9d7c02fb3ec87548cc2456904899b9d100c798ae2e08461dc8471b907664e38af99701adaaf6b604367ce70a72ce",
                // public key share 2
                "851d512dfbc25d2200982d70b107dad84bfef82d6f9fe9ce9c7bef7917755e3b2e504324ba2b7ed233b77f9c825188e8",
            ],
            // Trailing zero in the Public Key Set
            // This will fail any implementation with little endian shenaigans
            vec![
                "9455aa0495c1b0706507dd09531c71940e4cfeca1d5533dc096f4d5f045ba02f362790486e44e9d4a204938c65bd45208d19e0f29c53f6a1491c5aa24c4095759b57acccf1b801e5ea0270dac3c1e0d24a1058cbc4d8a3f185c1e87cefdaaa00",
                "9455aa0495c1b0706507dd09531c71940e4cfeca1d5533dc096f4d5f045ba02f362790486e44e9d4a204938c65bd4520",
                "881ffed3cc7a51355ffb1a99928ddfa16fb739ee7d4194e94e614ff0144d9978270cd2ffc0d2f95a664d450c4a7890c5",
                "b06db35fe602cbe651667aef2a77f53af1e8a4abb8764cec021d0aeac77728a5accc519bcfb07b609874fa76bd36452c",
                "856bb79f082919dfe2a4601765c2d6094ff122f494db7593a3eab2340136a50d7ad8ba20b09367c6c2b87a543cfee014",
            ],
            // Trailing zero in the Public Key
            vec![
                "afddb9cb9b636f176fd3e4d66ebf1d5e1b8feb0e43723e10fb4e4bc00bbbc3d29d6f6c8d7beca65fee2c89bd54e79e00a151ba6cea3fbe4b84bf14e99ef83edc1a805305ddeb998b93cb30c965abac057bd2dbfd73a00277638ec98da02b770c",
                "afddb9cb9b636f176fd3e4d66ebf1d5e1b8feb0e43723e10fb4e4bc00bbbc3d29d6f6c8d7beca65fee2c89bd54e79e00",
                "af121474a59ff060cb6b7862431cfc4ff6188c88120e0f686c790401d716ea6cd46a08201fcf88a0e96e324fcf08a25f",
                "b7ce6b16cfed4d94e95478902e64920bf95e84848bc471b569c547a4d59265be3865f6f1de40720045446ad9cd15b5ba",
                "a08b1043e38862e9442574d0afd1ed47c197d1dec2f0600edfedbb9e45cfac07095e15ddc8c6b91d0657272bb990d3e7",
            ],
            // Trailing zero in a Public Key Share
            vec![
                "8a4f064135d1a26d71b77f8d3f3a611e8f4de6489afb5b99e567aa6e93ee6a67f1e8fdde8105080382c822a52cf989ad833106149091a207a0e0fd3353e1a2c6dbe0147538a35b562e9b779252e8707c3cd98759a18a1c55cc7eb0f9f8440664",
                "8a4f064135d1a26d71b77f8d3f3a611e8f4de6489afb5b99e567aa6e93ee6a67f1e8fdde8105080382c822a52cf989ad",
                "907ec2454a752d18a172cb7c99d5f7952a558bdbd2675c107aeb84f0281f39cf72022e3ec26d05e86809ee0e2ebe352a",
                "8bd292ce33c1bcec80ce6cf029aeac292d9563d6e718fdcd8573188f88364442f2a8d51f1124b69c48fe5adc77512800",
                "aa4f3dbd12d6184bb5426187e46d20df9c160b4c5f9028b73fc904c988405e8655f1eaf979992a163d03d601f39efce1",
            ]
        ];
        for vector in vectors {
            // read PublicKeyShare from hex
            let pks_bytes = hex::decode(vector[0]).unwrap();
            let pks = PublicKeySet::from_bytes(pks_bytes).expect("Invalid public key set bytes");
            // check public key
            let pk = pks.public_key();
            let pk_hex = &format!("{}", HexFmt(&pk.to_bytes()));
            assert_eq!(pk_hex, vector[1]);
            // check public key shares
            let pk_share_0 = pks.public_key_share(0);
            let pk_share_0_hex = &format!("{}", HexFmt(&pk_share_0.to_bytes()));
            assert_eq!(pk_share_0_hex, vector[2]);
            let pk_share_1 = pks.public_key_share(1);
            let pk_share_1_hex = &format!("{}", HexFmt(&pk_share_1.to_bytes()));
            assert_eq!(pk_share_1_hex, vector[3]);
            let pk_share_2 = pks.public_key_share(2);
            let pk_share_2_hex = &format!("{}", HexFmt(&pk_share_2.to_bytes()));
            assert_eq!(pk_share_2_hex, vector[4]);
        }
    }

    #[test]
    fn test_secret_key_set_to_from_bytes_distictive_properties() {
        let threshold = 3;
        let mut rng = rand::thread_rng();
        let poly = Poly::random(threshold, &mut rng);
        let sk_set = SecretKeySet::from(poly);
        // length is fixed to (threshold + 1) * 32
        let sk_set_bytes = sk_set.to_bytes();
        assert_eq!(sk_set_bytes.len(), (threshold + 1) * SK_SIZE);
        // the first bytes of the secret key set match the secret key
        let sk = sk_set.secret_key();
        let sk_bytes = sk.to_bytes();
        let sk_bytes_size = sk_bytes.len();
        for i in 0..sk_bytes_size {
            assert_eq!(sk_bytes[i], sk_set_bytes[i]);
        }
        // from bytes gives original sk set
        let restored_sk_set =
            SecretKeySet::from_bytes(sk_set_bytes).expect("invalid secret key set bytes");
        // cannot assert_eq! for SecretKeySet so test the secret_key
        // TODO decide if testing the secret key is adequate for testing the
        // entire restored secret key set
        let restored_sk = restored_sk_set.secret_key();
        assert_eq!(sk, restored_sk);
    }

    #[test]
    fn test_secret_key_set_to_from_bytes_threshold_0() {
        // for threshold 0 the secret key set matches the secret key and all
        // secret key shares
        let threshold = 0;
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(threshold, &mut rng);
        let sk_set_bytes = sk_set.to_bytes();
        let sk = sk_set.secret_key();
        let sk_bytes = sk.to_bytes();
        assert_eq!(sk_set_bytes, sk_bytes);
        let sk_share_0 = sk_set.secret_key_share(0);
        let sk_share_0_bytes = sk_share_0.to_bytes();
        assert_eq!(sk_set_bytes, sk_share_0_bytes);
        let sk_share_1 = sk_set.secret_key_share(1);
        let sk_share_1_bytes = sk_share_1.to_bytes();
        assert_eq!(sk_set_bytes, sk_share_1_bytes);
    }

    #[test]
    fn vectors_secret_key_set_to_from_bytes() {
        let vectors = vec![
            // Plain old Secret Key Set
            // Sourced from Poly::reveal and SecretKey::reveal
            vec![
                // secret key set
                "474da5f155b0580b6ffcd28b62973226883bfc75658a06c2592175448221f68f64681c46c8de0e28f0666b6a849463e07a8a353bbd4b01457c0aeeb6e7dd1fa6",
                // secret key
                "474da5f155b0580b6ffcd28b62973226883bfc75658a06c2592175448221f68f",
                // secret key share 0
                "37c81ae4f4f0e8ec2d2965eddd89be01af088dae22d6ac08d52c63fc69ff1634",
                // secret key share 1
                "28428fd8943179ccea55f950587c49dcd5d51ee6e023514f513752b451dc35d9",
                // secret key share 2
                "18bd04cc33720aada7828cb2d36ed5b7fca1b01f9d6ff695cd42416c39b9557e",
            ],
            // Leading byte of Secret Key Set is zero
            // Also covers the Secret Key with a leading zero
            // This will fail for implementations with incorrect padding
            vec![
                "004e7590e4a4a97685f4d9f2c10cd8b71c88fead21f701701ddb2ee9c2d2047f015ea5a4ffc5ae4830f5dae1d0b3fed09b9bbebb983c1fc7d79b351361ba075a",
                "004e7590e4a4a97685f4d9f2c10cd8b71c88fead21f701701ddb2ee9c2d2047f",
                "01ad1b35e46a57beb6eab4d491c0d787b824bd68ba332137f57663fd248c0bd9",
                "030bc0dae4300606e7e08fb66274d65853c07c24526f40ffcd11991086461333",
                "046a667fe3f5b44f18d66a983328d528ef5c3adfeaab60c7a4acce23e8001a8d",
            ],
            // Leading byte of Secret Key Share is zero
            vec![
                "1c838171bcbb0c20e3f259cadcba86e611eb4587f069a6dcd5ee46f186e37039579311c4b4d7d016c3cae22fad69c8b8f5ce17ac826c8fefd6b38b746dd83cf8",
                "1c838171bcbb0c20e3f259cadcba86e611eb4587f069a6dcd5ee46f186e37039",
                "0028ebe347f55eef748363f280827799b3fbb93172d7dacdaca1d266f4bbad30",
                "57bbfda7fccd2f06384e46222dec4052a9c9d0ddf5446abd83555ddb6293ea28",
                "3b616819880781d4c8df5049d1b431064bda448777b29eae5a08e950d06c271f",
            ],
        ];
        for vector in vectors {
            // read SecretKeyShare from hex
            let sks_bytes = hex::decode(vector[0]).unwrap();
            let sks = SecretKeySet::from_bytes(sks_bytes).expect("invalid secret key set bytes");
            // check secret key
            let sk = sks.secret_key();
            let sk_hex = &format!("{}", HexFmt(&sk.to_bytes()));
            assert_eq!(sk_hex, vector[1]);
            // check secret key shares
            let sk_share_0 = sks.secret_key_share(0);
            let sk_share_0_hex = &format!("{}", HexFmt(&sk_share_0.to_bytes()));
            assert_eq!(sk_share_0_hex, vector[2]);
            let sk_share_1 = sks.secret_key_share(1);
            let sk_share_1_hex = &format!("{}", HexFmt(&sk_share_1.to_bytes()));
            assert_eq!(sk_share_1_hex, vector[3]);
            let sk_share_2 = sks.secret_key_share(2);
            let sk_share_2_hex = &format!("{}", HexFmt(&sk_share_2.to_bytes()));
            assert_eq!(sk_share_2_hex, vector[4]);
        }
    }

    #[test]
    fn test_decryption_share_to_from_bytes() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let msg = b"Totally real news";
        let ciphertext = pk_set.public_key().encrypt(&msg[..]);
        let dec_share = sk_set
            .secret_key_share(8)
            .decrypt_share(&ciphertext)
            .expect("ciphertext is invalid");
        let dec_share_bytes = dec_share.to_bytes();
        let restored_dec_share =
            DecryptionShare::from_bytes(dec_share_bytes).expect("invalid decryption share bytes");
        assert_eq!(dec_share, restored_dec_share);
    }

    #[test]
    fn test_derive_child_secret_key() {
        let sk = SecretKey::random();
        // derivation index 0
        let child0 = sk.derive_child(&[0]);
        assert!(child0 != sk);
        // derivation index 00
        let child00 = sk.derive_child(&[0, 0]);
        assert!(child00 != sk);
        assert!(child00 != child0);
        // derivation index 1
        let child1 = sk.derive_child(&[1]);
        assert!(child1 != sk);
        assert!(child1 != child0);
        // derivation index 2
        let child2 = sk.derive_child(&[2]);
        assert!(child2 != sk);
        assert!(child2 != child0);
        assert!(child2 != child1);
        // derivation index 3
        let child3 = sk.derive_child(&[3]);
        assert!(child3 != sk);
        assert!(child3 != child0);
        assert!(child3 != child0);
        assert!(child3 != child1);
        assert!(child3 != child2);
        // very large derivation index can be used, eg 100 bytes
        let index100b = [3u8; 100];
        let child100b = sk.derive_child(&index100b);
        assert!(child100b != sk);
    }

    #[test]
    fn test_derive_child_public_key() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        // the derived keypair is a match
        let child_sk = sk.derive_child(&[0]);
        let child_pk = pk.derive_child(&[0]);
        assert_eq!(child_pk, child_sk.public_key());
    }

    #[test]
    fn test_derivation_index_into_fr() {
        // index 0 does not give Fr::zero
        let fr_from_0 = derivation_index_into_fr(&[0]);
        assert!(fr_from_0 != Fr::zero());
        // index 1 does not give Fr::one
        let fr_from_1 = derivation_index_into_fr(&[1]);
        assert!(fr_from_1 != Fr::one());
        // index > q gives valid Fr that isn't Fr::MAX
        // the check relies on the fact Fr::MAX + 1 = 0
        let mut fr_from_2pow256 = derivation_index_into_fr(&[255u8; 32]);
        fr_from_2pow256.add_assign(&Fr::one());
        assert!(fr_from_2pow256 != Fr::zero());
    }

    #[test]
    fn test_derive_child_key_vectors() {
        let vectors = vec![
            // Plain old derivation
            vec![
                // secret key
                "474da5f155b0580b6ffcd28b62973226883bfc75658a06c2592175448221f68f",
                // public key
                "ac378101f72ddf89998b3b20f9498bec1443fb095bbdaa40ad8e0cbc1fe73a147e304a14cce88bc4bd23da1e45eb3742",
                // random index
                "57cb1459985906a9c00036f0b1d700b52a4dc25b3e0ff3808dd2c9fa6ca6ba87",
                // child secret key at random index
                "4039a5958f0a10baa1d1f0d5d7e06435a126744e8b656289e74d74241492df89",
                // child public key at random index
                "b46666bbe6f6315df6cacd8200566a977d1875a09b233b0ea60ecd8ee4ffda6f2e1d2cd28665b60f48682f8d14a95a04",
            ],
            vec![
                // secret key
                "0000000000000000000000000000000000000000000000000000000000000003",
                // public key
                "89ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224",
                // index 0
                "00",
                // child secret key at index 0
                "46b9a6b0b09523de44c2df70650e93320ec9d252c89b7a9eedcebacc0b96ad7a",
                // child public key at index 0
                "813695785a144e84c48c2a5644772514b6a58503f675f9c77ddfb7513eeb44888031f3ffe6b907a7f3889817a0de3abe",
                // index 1
                "01",
                // child secret key at index 1
                "633a4afa473971245620d27dc5778102d000fff80fa15ce06e74e1f610a50493",
                // child public key at index 1
                "8fd67eac24b4673a00000f57d40e10852eef9fda2800dff003536e3042a6ac5973f0709776c6c93191df4f0d7daf7e46",
                // index 2
                "02",
                // child secret key at index 2
                "2cc4bf8dd81c619e41146c963e00a245c6cf00163c2932132908f76edf539c7f",
                // child public key at index 2
                "8ab99d21622d98ad8bea68c5db881298f317fac691db1ae1eef191407107978338383ef8408fca0743997d040dab27c1",
                // index 1 with left padding
                // different to single byte index "01"
                "0000000000000000000000000000000000000000000000000000000000000001",
                // child secret key for 1 with left padding
                "35f65c516e54a08e29f4f9996738dbfc33f5e1a22b023082ff9f01a4a507fc7c",
                // child public key for 1 with left padding
                "81a2a9a1b3c891701dba0bdbe975bb06ff20947a35519e7938da7a783b0d561694ae5a9c2ec0c0011fc899dae67e11aa",
                // index 1 with right padding
                // different to single byte index "01"
                "0100000000000000000000000000000000000000000000000000000000000000",
                // child secret key for 1 with right padding
                "49df2b6e5b2d4310f8419d8ea651c790e502884c0b9e903c65d23c2f3d522f8b",
                // child public key for 1 with right padding
                "a2479d4554fbf8bc98f206bb09de80e2790f44fa3ea8f0cb02c44116111c60da2691683b17367cbb933c27836d721206",
                // index with 17 bytes
                "0000000000000000000000000000000101",
                // child secret key for 17 bytes
                "65a44b4096fb8948d42a762c27141f58b678de54b9cba554f13e8e144f1ed889",
                // child public key for 17 bytes
                "b2a88bac72330a081500b3b27698664812039b61d6929d3ed0a4fea28a4ae35ebc72a149a8d8b2534860672b4348e7ef",
                // large index greater than q
                "fedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedc",
                // child secret key at large index
                "3da527e935752a7924b8b244be2b6e4b6a8ef54865ef7e1dfeae5187d1cf414d",
                // child public key at large index
                "85954d86b7028b362d43e8d8319ef529a8d69c5a4b0a9352f6d3f10d9aa9a5d44b576f14087882d6d51fd10b70e228e9",
                // index with more than 256 bits
                // note different to single byte index "00"
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                // child secret key for index more than 256 bits
                "50524fce1903b24900bd7ae12fce29d3e7cf0520f5fbaee08bc8efe9922458c0",
                // child public key for index more than 256 bits
                "a419c001ca4f8261388f0ca55a43ded57f741d2833c532450bded670dad3b0654f2c7ffa81ca9a1fa7b03639d1fd9171",
                // index with many repeated hashes (34 rounds for this index)
                "0000000028c0acd2",
                // child secret key for index with main repeated hashes
                "319e0ac479cff5cb4261e465de3736d634c583bcb5a1ac33fb0dcb1d77908268",
                // child public key for index with many repeated hashes
                "86037c3f7fbd88572bd56025444bb2a49375d2e146f9a52d8a35689fd93d04ebc62559a1441cdc7edbf39189247b9620",
                // index with child secret key leading zero
                "0000000000000017",
                // child secret key for sk leading zero
                "00dc1689706a2de1f9b84b647776f200c61de5ba2699ab4be6890d96e7870ef8",
                // child public key for sk leading zero
                "825cb1914a0b5f006d529b081c06b04f334c8c97456e83a4e61917ce6b5256dab462575b1c03a9bed913bf1c070fda0d",
                // index with child public key trailing zero
                "0000000000000152",
                // child secret key for child pk trailing zero
                "4237e4e30390f33a329107edde05130ce84e403e0f78a0ba4e5dea79289ba200",
                // child public key for child pk trailing zero
                "adb936c7a97c9c98c80b92635ce6ffaceba6620d133ddc7252bd5d11cf7c7a3aa3bbda9428f860987655820a9e940fd8",
            ],
        ];
        for vector in vectors {
            // get parent keypair
            let sk_vec = hex::decode(vector[0]).unwrap();
            let mut sk_bytes = [0u8; SK_SIZE];
            sk_bytes[..SK_SIZE].clone_from_slice(&sk_vec[..SK_SIZE]);
            let sk = SecretKey::from_bytes(sk_bytes).expect("invalid secret key bytes");
            let pk = sk.public_key();
            let pk_hex = &format!("{}", HexFmt(&pk.to_bytes()));
            assert_eq!(pk_hex, vector[1]);
            // test derivation for all the indexes
            let children = (vector.len() - 2) / 3;
            for i in 0..children {
                let v = 2 + i * 3;
                // get index
                let index = hex::decode(vector[v]).unwrap();
                // derive child secret key at this index
                let sk_child = sk.derive_child(&index);
                let sk_child_hex = &format!("{}", HexFmt(&sk_child.to_bytes()));
                assert_eq!(sk_child_hex, vector[v + 1]);
                // derive child public key at this index
                let pk_child = pk.derive_child(&index);
                let pk_child_hex = &format!("{}", HexFmt(&pk_child.to_bytes()));
                assert_eq!(pk_child_hex, vector[v + 2]);
                // confirm these keys are a pair
                assert_eq!(sk_child.public_key(), pk_child);
            }
        }
    }

    #[test]
    fn test_ciphertext_vectors() {
        let vectors = vec![
            // Plain old ciphertext
            vec![
                // secret key
                "09f82926174f2fb52fc3674822497362df34186b4cac60ab531d81ac36144b63",
                // plain text hex
                "0102030405",
                // ciphertext
                "96f6ab7884f1d1627439df210ce0c192071612a2fe212ec4bf3c70a885be007c7514dc15b769ef02f92558e862d2894e95f892f1eb4a8cfb6f05ac83adcb5b429261bc8b195830d92a59859135157b1f3394156dba1e905f29158d0eeea49faa0238bc51704cfcffdab35fb0d4ca9311bbb5b80d616be2d505d8f82a2ff4e69e756cc835b19e622f5b94457ad9c084e91de6b13d27",
            ],
            // Leading zeros and trailing
            vec![
                // secret key
                "0055555555555555555555555555555555555555555555555555555555555500",
                // plain text hex
                "00bdc600",
                // ciphertext with u and w having trailing zeros
                "b01724be1ed730f0b1713c24aa5963bff7845a56892b78b1a24152dfe48848223ea54a358c27946323ec013ee46af80088f508ef7ce6abf174f51dbfa5692adc975fa99a569860cff555b3e7f68d06dfe6dd2621643ec859a64e61cee1f9aced1569b695253936197585696cfab0b38dfd159051ec569e0d3ba1bb0d2a3dec008467810621111fb2dd92c44ef251280038164cb6",
            ],
        ];
        for vector in vectors {
            // get secret key
            let sk_vec = hex::decode(vector[0]).unwrap();
            let mut sk_bytes = [0u8; SK_SIZE];
            sk_bytes[..SK_SIZE].clone_from_slice(&sk_vec[..SK_SIZE]);
            let sk = SecretKey::from_bytes(sk_bytes).expect("invalid secret key bytes");
            // get ciphertext
            let ct_vec = hex::decode(vector[2]).unwrap();
            let ct = Ciphertext::from_bytes(&ct_vec).expect("invalid ciphertext bytes");
            // check the ciphertext is valid
            assert!(ct.verify());
            // check the decrypted ciphertext matches the original message
            let msg_vec = hex::decode(vector[1]).unwrap();
            let plaintext = sk.decrypt(&ct).expect("decryption failed");
            assert_eq!(plaintext, msg_vec);
        }
    }

    #[test]
    fn test_sk_set_derive_child() {
        let mut rng = rand::thread_rng();
        let sks = SecretKeySet::random(3, &mut rng);
        // Deriving from master is the same as deriving a set
        // and getting the master from the derived set
        let mut index = [0u8; 32];
        rng.fill_bytes(&mut index);
        let msk = sks.secret_key();
        let msk_child = msk.derive_child(&index);
        assert_ne!(msk, msk_child);
        let sks_child = sks.derive_child(&index);
        assert_ne!(sks.to_bytes(), sks_child.to_bytes());
        let sks_child_master = sks_child.secret_key();
        assert_eq!(msk_child, sks_child_master);
        // secret key shares are matching
        // sks.child(x).share(y) == sks.share(y).child(x)
        let sks_share0 = sks.secret_key_share(0);
        let sks_share0_child = sks_share0.derive_child(&index);
        let sks_child_share0 = sks_child.secret_key_share(0);
        assert_eq!(sks_share0_child, sks_child_share0);
    }

    #[test]
    fn test_pk_set_derive_child() {
        let mut rng = rand::thread_rng();
        let sks = SecretKeySet::random(3, &mut rng);
        let pks = sks.public_keys();
        // Deriving from master is the same as deriving a set
        // and getting the master from the derived set
        let mut index = [0u8; 32];
        rng.fill_bytes(&mut index);
        let mpk = pks.public_key();
        let mpk_child = mpk.derive_child(&index);
        assert_ne!(mpk, mpk_child);
        let pks_child = pks.derive_child(&index);
        assert_ne!(pks.to_bytes(), pks_child.to_bytes());
        let pks_child_master = pks_child.public_key();
        assert_eq!(mpk_child, pks_child_master);
        // public key shares are matching
        // pks.child(x).share(y) == pks.share(y).child(x)
        let pks_share0 = pks.public_key_share(0);
        let pks_share0_child = pks_share0.derive_child(&index);
        let pks_child_share0 = pks_child.public_key_share(0);
        assert_eq!(pks_share0_child, pks_child_share0);
        // derived master public key is a pair for derived master secret key
        let sks_child = sks.derive_child(&index);
        assert_eq!(sks_child.secret_key().public_key(), pks_child.public_key());
    }

    #[test]
    fn test_sk_set_child_sig() {
        // combining signatures from child keyshares produces
        // a valid signature for the child public key set
        let mut rng = rand::thread_rng();
        // The threshold is 3, so 4 signature shares will suffice to decrypt.
        let sks = SecretKeySet::random(3, &mut rng);
        let share_indexes = vec![5, 8, 7, 10];
        // all participants have the public key set and their key share.
        let pks = sks.public_keys();
        let key_shares: BTreeMap<_, _> = share_indexes
            .iter()
            .map(|&i| {
                let key_share = sks.secret_key_share(i);
                (i, key_share)
            })
            .collect();
        // all participants use the same index to derive a child keyshare
        let mut index = [0u8; 32];
        rng.fill_bytes(&mut index);
        let child_key_shares: BTreeMap<_, _> = key_shares
            .iter()
            .map(|(i, key_share)| {
                let child_key_share = key_share.derive_child(&index);
                (i, child_key_share)
            })
            .collect();
        // all participants sign a message with their child keyshare
        let msg = "Totally real news";
        let child_sig_shares: BTreeMap<_, _> = child_key_shares
            .iter()
            .map(|(i, child_key_share)| {
                let child_sig_share = child_key_share.sign(&msg);
                (i, child_sig_share)
            })
            .collect();
        // Combining the child shares creates a valid signature for the child
        // public key set.
        let pks_child = pks.derive_child(&index);
        let sig = pks_child
            .combine_signatures(&child_sig_shares)
            .expect("signatures match");
        assert!(pks_child.public_key().verify(&sig, msg));
    }
}
