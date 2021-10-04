//! A pairing-based threshold cryptosystem for collaborative decryption and signatures.

// Clippy warns that it's dangerous to derive `PartialEq` and explicitly implement `Hash`, but the
// `pairing::bls12_381` types don't implement `Hash`, so we can't derive it.
#![allow(clippy::derive_hash_xor_eq)]
#![warn(missing_docs)]

mod blst_ops;
mod into_fr;
mod secret;

pub mod error;
pub mod poly;
pub mod util;

use std::borrow::Borrow;
use std::fmt;
use std::vec::Vec;

use hex_fmt::HexFmt;
use rand::distributions::{Distribution, Standard};
use rand::{rngs::OsRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use zeroize::Zeroize;

use crate::poly::{Commitment, Poly};
use crate::secret::clear_fr;

pub use self::error::{Error, Result};
pub use crate::into_fr::IntoFr;

use blst_ops::{
    equal_pairs, fr_add_assign, fr_from_be_bytes, fr_inverse, fr_mul_assign, fr_mul_fr,
    fr_sub_assign, fr_sub_fr, fr_to_be_bytes, p1_add_assign, p1_from_be_bytes, p1_mul_fr,
    p1_to_be_bytes, p2_add_assign, p2_from_be_bytes, p2_mul_fr, p2_to_be_bytes, FR_ONE, FR_ZERO,
    P1_ONE,
};
use util::{derivation_index_into_fr, fr_random, sha3_256};

use blst::{blst_fr, blst_hash_to_g2, blst_p1, blst_p2};

/// The size of a secret key's representation in bytes.
pub const SK_SIZE: usize = 32;

/// The size of a key's representation in bytes.
pub const PK_SIZE: usize = 48;

/// The size of a signature's representation in bytes.
pub const SIG_SIZE: usize = 96;

/// The domain separator tag
pub const DST: &[u8; 43] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// A public key.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct PublicKey(blst_p1);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let l0 = (self.0).x.l[0]; // TODO IC check this
        write!(f, "PublicKey({:0.10})", HexFmt(l0.to_be_bytes()))
    }
}

impl PublicKey {
    /// Returns `true` if the signature matches the element of `G2`.
    pub fn verify_g2(&self, sig: &Signature, hash: &blst_p2) -> bool {
        equal_pairs(&self.0, hash, &P1_ONE, &sig.0)
    }

    /// Returns `true` if the signature matches the message.
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &Signature, msg: M) -> bool {
        self.verify_g2(sig, &hash_g2(msg))
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
        let r = fr_random(rng);
        let u = p1_mul_fr(&P1_ONE, &r);
        let v: Vec<u8> = {
            let g = p1_mul_fr(&self.0, &r);
            xor_with_hash(g, msg.as_ref())
        };
        let hash = hash_g1_g2(u, &v);
        let w = p2_mul_fr(&hash, &r);
        Ciphertext(u, v, w)
    }

    /// Derives a child public key for a given index.
    pub fn derive_child<T: IntoFr>(&self, index: T) -> Self {
        let index_fr = derivation_index_into_fr(index);
        let child_p1 = p1_mul_fr(&self.0, &index_fr);
        PublicKey(child_p1)
    }

    /// Returns the key with the given representation, if valid.
    pub fn from_bytes(bytes: [u8; PK_SIZE]) -> Result<Self> {
        let p1 = p1_from_be_bytes(bytes)?;
        Ok(PublicKey(p1))
    }

    /// Returns a byte string representation of the public key.
    pub fn to_bytes(self) -> [u8; PK_SIZE] {
        p1_to_be_bytes(&self.0)
    }
}

/// A public key share.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyShare(PublicKey);

impl fmt::Debug for PublicKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let l0 = (self.0).0.x.l[0]; // TODO IC check this
        write!(f, "PublicKeyShare({:0.10})", HexFmt(l0.to_be_bytes()))
    }
}

impl PublicKeyShare {
    /// Returns `true` if the signature matches the element of `G2`.
    pub fn verify_g2(&self, sig: &SignatureShare, hash: &blst_p2) -> bool {
        self.0.verify_g2(&sig.0, hash)
    }

    /// Returns `true` if the signature matches the message.
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &SignatureShare, msg: M) -> bool {
        self.verify_g2(sig, &hash_g2(msg))
    }

    /// Returns `true` if the decryption share matches the ciphertext.
    pub fn verify_decryption_share(&self, share: &DecryptionShare, ct: &Ciphertext) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *ct;
        let hash = hash_g1_g2(*u, v);
        equal_pairs(&share.0, &hash, &(self.0).0, w)
    }

    /// Derives a child public key share for a given index.
    pub fn derive_child<T: IntoFr>(&self, index: T) -> Self {
        PublicKeyShare(self.0.derive_child(index))
    }

    /// Returns the key share with the given representation, if valid.
    pub fn from_bytes(bytes: [u8; PK_SIZE]) -> Result<Self> {
        Ok(PublicKeyShare(PublicKey::from_bytes(bytes)?))
    }

    /// Returns a byte string representation of the public key share.
    pub fn to_bytes(self) -> [u8; PK_SIZE] {
        self.0.to_bytes()
    }
}

/// A signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(blst_p2);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let l0 = (self.0).x.fp[0].l[0]; // TODO IC check this
        write!(f, "Signature({:0.10})", HexFmt(l0.to_be_bytes()))
    }
}

impl Signature {
    /// Returns the signature with the given representation, if valid.
    pub fn from_bytes(bytes: [u8; SIG_SIZE]) -> Result<Self> {
        let p2 = p2_from_be_bytes(bytes)?;
        Ok(Signature(p2))
    }

    /// Returns a byte string representation of the signature.
    pub fn to_bytes(&self) -> [u8; SIG_SIZE] {
        p2_to_be_bytes(&self.0)
    }
}

/// A signature share.
#[derive(Clone, PartialEq, Eq)]
pub struct SignatureShare(pub Signature);

impl fmt::Debug for SignatureShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let l0 = ((self.0).0).x.fp[0].l[0]; // TODO IC check this
        write!(f, "SignatureShare({:0.10})", HexFmt(l0.to_be_bytes()))
    }
}

impl SignatureShare {
    /// Returns the signature share with the given representation, if valid.
    pub fn from_bytes(bytes: [u8; SIG_SIZE]) -> Result<Self> {
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
pub struct SecretKey(blst_fr);

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
        let mut fr = FR_ZERO;
        SecretKey::from_mut(&mut fr)
    }
}

impl Distribution<SecretKey> for Standard {
    /// Creates a new random instance of `SecretKey`. If you do not need to specify your own RNG,
    /// you should use the [`SecretKey::random()`](struct.SecretKey.html#method.random) constructor,
    /// which uses [`rand::thread_rng()`](https://docs.rs/rand/0.7.2/rand/fn.thread_rng.html)
    /// internally as its RNG.
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SecretKey {
        SecretKey(fr_random(rng))
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
    pub fn from_mut(fr: &mut blst_fr) -> Self {
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
        let p1 = p1_mul_fr(&P1_ONE, &self.0);
        PublicKey(p1)
    }

    /// Signs the given element of `G2`.
    pub fn sign_g2(&self, hash: &blst_p2) -> Signature {
        let sig = p2_mul_fr(hash, &self.0);
        Signature(sig)
    }

    /// Signs the given message.
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> Signature {
        self.sign_g2(&hash_g2(msg))
    }

    /// Converts the secret key to big endian bytes
    pub fn to_bytes(&self) -> [u8; SK_SIZE] {
        fr_to_be_bytes(self.0)
    }

    /// Deserialize from big endian bytes
    pub fn from_bytes(bytes: [u8; SK_SIZE]) -> Result<Self> {
        let mut fr = fr_from_be_bytes(bytes)?;
        Ok(SecretKey::from_mut(&mut fr))
    }

    /// Returns the decrypted text, or `None`, if the ciphertext isn't valid.
    pub fn decrypt(&self, ct: &Ciphertext) -> Option<Vec<u8>> {
        if !ct.verify() {
            return None;
        }
        let Ciphertext(ref u, ref v, _) = *ct;
        let g = p1_mul_fr(u, &self.0);
        Some(xor_with_hash(g, v))
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field element.
    pub fn reveal(&self) -> String {
        format!("SecretKey({:?})", self.0)
    }

    /// Derives a child secret key for a given index.
    pub fn derive_child<T: IntoFr>(&self, index: T) -> Self {
        let index_fr = derivation_index_into_fr(index);
        let child = fr_mul_fr(&self.0, &index_fr);
        SecretKey(child)
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
    pub fn from_mut(fr: &mut blst_fr) -> Self {
        SecretKeyShare(SecretKey::from_mut(fr))
    }

    /// Returns the matching public key share.
    pub fn public_key_share(&self) -> PublicKeyShare {
        PublicKeyShare(self.0.public_key())
    }

    /// Signs the given element of `G2`.
    pub fn sign_g2(&self, hash: &blst_p2) -> SignatureShare {
        SignatureShare(self.0.sign_g2(hash))
    }

    /// Signs the given message.
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> SignatureShare {
        let signature = self.0.sign(msg);
        SignatureShare(signature)
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
        let u = ct.0;
        let u_mul_r = p1_mul_fr(&u, &(self.0).0);
        DecryptionShare(u_mul_r)
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field element.
    pub fn reveal(&self) -> String {
        format!("SecretKeyShare({:?})", (self.0).0)
    }

    /// Derives a child secret key share for a given index.
    pub fn derive_child<T: IntoFr>(&self, index: T) -> Self {
        SecretKeyShare(self.0.derive_child(index))
    }

    /// Serializes to big endian bytes
    pub fn to_bytes(&self) -> [u8; SK_SIZE] {
        self.0.to_bytes()
    }

    /// Deserializes from big endian bytes
    pub fn from_bytes(bytes: [u8; SK_SIZE]) -> Result<Self> {
        Ok(SecretKeyShare(SecretKey::from_bytes(bytes)?))
    }
}

/// An encrypted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext(blst_p1, Vec<u8>, blst_p2);

impl Ciphertext {
    /// Returns `true` if this is a valid ciphertext. This check is necessary to prevent
    /// chosen-ciphertext attacks.
    pub fn verify(&self) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *self;
        let hash = hash_g1_g2(*u, v);
        equal_pairs(&P1_ONE, w, u, &hash)
    }

    /// Returns byte representation of Ciphertext
    pub fn to_bytes(&self) -> Vec<u8> {
        let Ciphertext(ref u, ref v, ref w) = *self;
        let mut result: Vec<u8> = Default::default();
        result.extend(p1_to_be_bytes(u));
        result.extend(p2_to_be_bytes(w));
        result.extend(v);
        result
    }

    /// Returns the Ciphertext with the given representation, if valid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < PK_SIZE + SIG_SIZE + 1 {
            return Err(Error::InvalidBytes);
        }

        let mut u_bytes = [0u8; PK_SIZE];
        u_bytes.copy_from_slice(&bytes[0..PK_SIZE]);
        let u = p1_from_be_bytes(u_bytes)?;

        let mut w_bytes = [0u8; SIG_SIZE];
        w_bytes.copy_from_slice(&bytes[PK_SIZE..PK_SIZE + SIG_SIZE]);
        let w = p2_from_be_bytes(w_bytes)?;

        let v: Vec<u8> = (&bytes[PK_SIZE + SIG_SIZE..]).to_vec();

        Ok(Self(u, v, w))
    }
}

/// A decryption share. A threshold of decryption shares can be used to decrypt a message.
#[derive(Clone, PartialEq, Eq)]
pub struct DecryptionShare(blst_p1);

impl fmt::Debug for DecryptionShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DecryptionShare").field(&DebugDots).finish()
    }
}

impl DecryptionShare {
    /// Deserializes the share from big endian bytes
    pub fn from_bytes(bytes: [u8; PK_SIZE]) -> Result<Self> {
        let p1 = p1_from_be_bytes(bytes)?;
        Ok(DecryptionShare(p1))
    }

    /// Serializes the share as big endian bytes
    pub fn to_bytes(&self) -> [u8; PK_SIZE] {
        p1_to_be_bytes(&self.0)
    }
}

/// A public key and an associated set of public key shares.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKeySet {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    commit: Commitment,
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
    /// let sig_shares: BTreeMap<_, _> = (0..4).map(|i| (i, sk_shares[i].sign(msg).expect("failed to sign msg"))).collect();
    ///
    /// // Validate the signature shares.
    /// for (i, sig_share) in &sig_shares {
    ///     pk_set.public_key_share(*i).verify(sig_share, msg).expect("signature verification failed");
    /// }
    ///
    /// // Combine them to produce the main signature.
    /// let sig = pk_set.combine_signatures(&sig_shares).expect("not enough shares");
    ///
    /// // Validate the main signature. If the shares were valid, this can't fail.
    /// pk_set.public_key().verify(&sig, msg).expect("signature verification failed");
    /// ```
    pub fn combine_signatures<T, I, S: Borrow<SignatureShare>>(
        &self,
        shares: I,
    ) -> Result<Signature>
    where
        I: IntoIterator<Item = (T, S)>,
        T: IntoFr,
    {
        let samples = shares
            .into_iter()
            .map(|(i, share)| (i, (share.borrow().0).0));
        Ok(Signature(interpolate_g2(self.commit.degree(), samples)?))
    }

    /// Combines the shares to decrypt the ciphertext.
    pub fn decrypt<'a, T, I>(&self, shares: I, ct: &Ciphertext) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = (T, &'a DecryptionShare)>,
        T: IntoFr,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, share.0));
        let g = interpolate_g1(self.commit.degree(), samples)?;
        Ok(xor_with_hash(g, &ct.1))
    }

    /// Derives a child public key set for a given index.
    pub fn derive_child<T: IntoFr>(&self, index: T) -> Self {
        let index_fr = derivation_index_into_fr(index);
        let child_coeffs: Vec<blst_p1> = self
            .commit
            .coeff
            .iter()
            .map(|coeff| p1_mul_fr(coeff, &index_fr))
            .collect();
        PublicKeySet::from(Commitment::from(child_coeffs))
    }

    /// Serializes to big endian bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.commit.to_bytes()
    }

    /// Deserializes from big endian bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
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
    pub fn derive_child<T: IntoFr>(&self, index: T) -> Self {
        // Equivalent to self.poly.clone() * index_fr;
        // The code here follows the same structure as in PublicKeySet for
        // similarity / symmetry / aesthetics, since Commitment can't be
        // multiplied by Fr the same way Poly can.
        let index_fr = derivation_index_into_fr(index);
        let child_coeffs: Vec<blst_fr> = self
            .poly
            .coeff
            .iter()
            .map(|coeff| fr_mul_fr(coeff, &index_fr))
            .collect();
        SecretKeySet::from(Poly::from(child_coeffs))
    }

    /// Serializes to big endian bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.poly.to_bytes()
    }

    /// Deserializes from big endian bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let poly = Poly::from_bytes(bytes)?;
        Ok(SecretKeySet { poly })
    }
}

/// A blinded message.
#[derive(Clone, PartialEq, Eq)]
pub struct BlindedMessage(pub blst_p2);

impl fmt::Debug for BlindedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let l0 = (self.0).x.fp[0].l[0]; // TODO IC check this
        write!(f, "BlindedMsg({:0.10})", HexFmt(l0.to_be_bytes()))
    }
}

impl BlindedMessage {
    /// Returns the blinded message with the given representation, if valid.
    pub fn from_bytes(bytes: [u8; SIG_SIZE]) -> Result<Self> {
        let p2 = p2_from_be_bytes(bytes)?;
        Ok(BlindedMessage(p2))
    }

    /// Returns a byte string representation of the blinded message.
    pub fn to_bytes(&self) -> [u8; SIG_SIZE] {
        p2_to_be_bytes(&self.0)
    }
}

/// Returns a hash of the given message in `G2`.
pub fn hash_g2<M: AsRef<[u8]>>(msg: M) -> blst_p2 {
    let mut p2 = blst_p2::default();
    let aug = b"";
    unsafe {
        blst_hash_to_g2(
            &mut p2,
            msg.as_ref().as_ptr(),
            msg.as_ref().len(),
            DST.as_ptr(),
            DST.len(),
            aug.as_ptr(),
            aug.len(),
        )
    };
    p2
}

/// Blinds a message for signing by an authority.
pub fn blind_message<M: AsRef<[u8]>>(msg: M, blinding_factor: &blst_fr) -> BlindedMessage {
    let hash = hash_g2(msg);
    let blinded_hash = p2_mul_fr(&hash, blinding_factor);
    BlindedMessage(blinded_hash)
}

/// Unblinds a blind signature after being signed by an authority.
pub fn unblind_signature(blinded_sig: &Signature, blinding_factor: &blst_fr) -> Signature {
    let mut bf_inv = *blinding_factor;
    fr_inverse(&mut bf_inv);
    let unblinded_sig = p2_mul_fr(&blinded_sig.0, &bf_inv);
    Signature(unblinded_sig)
}

/// Returns a hash of the group element and message, in the second group.
fn hash_g1_g2<M: AsRef<[u8]>>(g1: blst_p1, msg: M) -> blst_p2 {
    // If the message is large, hash it, otherwise copy it.
    // TODO: Benchmark and optimize the threshold.
    let mut msg = if msg.as_ref().len() > 64 {
        sha3_256(msg.as_ref()).to_vec()
    } else {
        msg.as_ref().to_vec()
    };
    let p1_bytes = p1_to_be_bytes(&g1);
    msg.extend(p1_bytes);
    hash_g2(&msg)
}

/// Returns the bitwise xor of `bytes` with a sequence of pseudorandom bytes determined by `g1`.
fn xor_with_hash(g1: blst_p1, bytes: &[u8]) -> Vec<u8> {
    let p1_bytes = p1_to_be_bytes(&g1);
    let digest = sha3_256(&p1_bytes);
    let rng = ChaChaRng::from_seed(digest);
    let xor = |(a, b): (u8, &u8)| a ^ b;
    rng.sample_iter(&Standard).zip(bytes).map(xor).collect()
}

/// Given a list of `t + 1` samples `(i - 1, f(i) * g)` for a polynomial `f` of degree `t`, and a
/// group generator `g`, returns `f(0) * g`.
fn interpolate_g1<T, I>(t: usize, items: I) -> Result<blst_p1>
where
    I: IntoIterator<Item = (T, blst_p1)>,
    T: IntoFr,
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
    let mut x_prod: Vec<blst_fr> = Vec::with_capacity(t);
    let mut tmp = FR_ONE;
    x_prod.push(tmp);
    for (x, _) in samples.iter().take(t) {
        fr_mul_assign(&mut tmp, x);
        x_prod.push(tmp);
    }
    tmp = FR_ONE;
    for (i, (x, _)) in samples[1..].iter().enumerate().rev() {
        fr_mul_assign(&mut tmp, x);
        fr_mul_assign(&mut x_prod[i], &tmp);
    }

    let mut result = blst_p1::default();
    for (mut l0, (x, sample)) in x_prod.into_iter().zip(&samples) {
        // Compute the value at 0 of the Lagrange polynomial that is `0` at the other data
        // points but `1` at `x`.
        let mut denom = FR_ONE;
        for (x0, _) in samples.iter().filter(|(x0, _)| x0 != x) {
            let mut diff = *x0;
            fr_sub_assign(&mut diff, x);
            fr_mul_assign(&mut denom, &diff);
        }
        fr_inverse(&mut denom); //.ok_or(Error::DuplicateEntry)?;
        fr_mul_assign(&mut l0, &denom);
        let sample_mul = p1_mul_fr(sample, &l0);
        p1_add_assign(&mut result, &sample_mul);
    }
    Ok(result)
}

/// Given a list of `t + 1` samples `(i - 1, f(i) * g)` for a polynomial `f` of degree `t`, and a
/// group generator `g`, returns `f(0) * g`.
fn interpolate_g2<T, I>(t: usize, items: I) -> Result<blst_p2>
where
    I: IntoIterator<Item = (T, blst_p2)>,
    T: IntoFr,
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
    let mut x_prod: Vec<blst_fr> = Vec::with_capacity(t);
    let mut tmp = FR_ONE;
    x_prod.push(tmp);
    for (x, _) in samples.iter().take(t) {
        fr_mul_assign(&mut tmp, x);
        x_prod.push(tmp);
    }
    tmp = FR_ONE;
    for (i, (x, _)) in samples[1..].iter().enumerate().rev() {
        fr_mul_assign(&mut tmp, x);
        fr_mul_assign(&mut x_prod[i], &tmp);
    }

    let mut result = blst_p2::default();
    for (mut l0, (x, sample)) in x_prod.into_iter().zip(&samples) {
        // Compute the value at 0 of the Lagrange polynomial that is `0` at the other data
        // points but `1` at `x`.
        let mut denom = FR_ONE;
        for (x0, _) in samples.iter().filter(|(x0, _)| x0 != x) {
            let diff = fr_sub_fr(x0, x);
            fr_mul_assign(&mut denom, &diff);
        }
        fr_inverse(&mut denom); //.ok_or(Error::DuplicateEntry)?
        fr_mul_assign(&mut l0, &denom);
        let sample_mul = p2_mul_fr(sample, &l0);
        p2_add_assign(&mut result, &sample_mul);
    }
    Ok(result)
}

fn into_fr_plus_1<I: IntoFr>(x: I) -> blst_fr {
    let mut xfr = x.into_fr();
    fr_add_assign(&mut xfr, &FR_ONE);
    xfr
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

    use eyre::{eyre, Result};
    use std::collections::BTreeMap;

    use rand::{self, distributions::Standard, random, Rng};

    #[test]
    fn test_interpolate() {
        let mut rng = rand::thread_rng();
        for deg in 0..5 {
            let comm = Poly::random(deg, &mut rng).commitment();
            let mut values = Vec::new();
            let mut x = 0;
            for _ in 0..=deg {
                x += rng.gen_range(1, 5);
                values.push((x - 1, comm.evaluate(x)));
            }
            let actual = interpolate_g1(deg, values).expect("wrong number of values");
            assert_eq!(comm.evaluate(0), actual);
        }
    }

    #[test]
    fn test_simple_sig() -> Result<()> {
        let sk0 = SecretKey::random();
        let sk1 = SecretKey::random();
        let pk0 = sk0.public_key();
        let msg0 = b"Real news";
        let msg1 = b"Fake news";
        assert!(pk0.verify(&sk0.sign(msg0), msg0));
        assert!(!pk0.verify(&sk1.sign(msg0), msg0)); // Wrong key.
        assert!(!pk0.verify(&sk0.sign(msg1), msg0)); // Wrong message.
        Ok(())
    }

    #[test]
    fn test_threshold_sig() -> Result<()> {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let pk_master = pk_set.public_key();

        // Make sure the keys are different, and the first coefficient is the main key.
        assert_ne!(pk_master, pk_set.public_key_share(0u64).0);
        assert_ne!(pk_master, pk_set.public_key_share(1u64).0);
        assert_ne!(pk_master, pk_set.public_key_share(2u64).0);

        // Make sure we don't hand out the main secret key to anyone.
        let sk_master = sk_set.secret_key();
        let sk_share_0 = sk_set.secret_key_share(0u64).0;
        let sk_share_1 = sk_set.secret_key_share(1u64).0;
        let sk_share_2 = sk_set.secret_key_share(2u64).0;
        assert_ne!(sk_master, sk_share_0);
        assert_ne!(sk_master, sk_share_1);
        assert_ne!(sk_master, sk_share_2);

        let msg = "Totally real news";

        // The threshold is 3, so 4 signature shares will suffice to recreate the share.
        // note: this tests passing a Vec to ::combine_signatures (instead of BTreeMap)
        let mut sigs: Vec<(_, _)> = vec![];
        for i in [5, 8, 7, 10] {
            let sig = sk_set.secret_key_share(i).sign(msg);
            sigs.push((i, sig));
        }

        // Each of the shares is a valid signature matching its public key share.
        for (i, sig) in &sigs {
            assert!(pk_set.public_key_share(*i).verify(sig, msg));
        }

        // Combined, they produce a signature matching the main public key.
        let sig = pk_set.combine_signatures(sigs).expect("signatures match");
        assert!(pk_set.public_key().verify(&sig, msg));

        // A different set of signatories produces the same signature.
        let mut sigs2 = BTreeMap::default();
        for i in [42, 43, 44, 45] {
            let sig = sk_set.secret_key_share(i).sign(msg);
            sigs2.insert(i, sig);
        }

        let sig2 = pk_set.combine_signatures(&sigs2).expect("signatures match");
        assert_eq!(sig, sig2);

        Ok(())
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
        let rng = rand::thread_rng();
        let msg: Vec<u8> = rng.sample_iter(&Standard).take(1000).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();
        let g0 = SecretKey::random().public_key().0;
        let g1 = SecretKey::random().public_key().0;

        assert_eq!(hash_g1_g2(g0, &msg), hash_g1_g2(g0, &msg));
        assert_ne!(hash_g1_g2(g0, &msg), hash_g1_g2(g0, &msg_end0));
        assert_ne!(hash_g1_g2(g0, &msg_end0), hash_g1_g2(g0, &msg_end1));
        assert_ne!(hash_g1_g2(g0, &msg), hash_g1_g2(g1, &msg));
    }

    /// Some basic sanity checks for the `hash_bytes` function.
    #[test]
    fn test_xor_with_hash() {
        let g0 = SecretKey::random().public_key().0;
        let g1 = SecretKey::random().public_key().0;
        let xwh = xor_with_hash;
        assert_eq!(xwh(g0, &[0; 5]), xwh(g0, &[0; 5]));
        assert_ne!(xwh(g0, &[0; 5]), xwh(g1, &[0; 5]));
        assert_eq!(5, xwh(g0, &[0; 5]).len());
        assert_eq!(6, xwh(g0, &[0; 6]).len());
        assert_eq!(20, xwh(g0, &[0; 20]).len());
    }

    #[test]
    fn test_from_to_bytes() -> Result<()> {
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
        Ok(())
    }

    #[test]
    fn test_zeroize() {
        let zero_sk = SecretKey(FR_ZERO);

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
    fn test_interoperability() -> Result<()> {
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
        let sk = SecretKey::from_bytes(skbytes).expect("invalid sk bytes");
        let pk = sk.public_key();
        // secret key gives same public key
        assert_eq!(pkbytes, pk.to_bytes());
        // signature matches test vector
        let sig = sk.sign(&msgbytes);
        assert_eq!(sigbytes, sig.to_bytes());
        // signature can be verified
        assert!(pk.verify(&sig, msgbytes));
        Ok(())
    }

    #[test]
    fn test_sk_to_from_bytes() -> Result<()> {
        let sk = SecretKey::random();
        let sk_be_bytes = sk.to_bytes();
        let restored_sk = SecretKey::from_bytes(sk_be_bytes).expect("invalid sk bytes");
        assert_eq!(sk, restored_sk);
        Ok(())
    }

    #[test]
    fn vectors_sk_to_from_bytes() -> Result<()> {
        // from https://github.com/Chia-Network/bls-signatures/blob/ee71adc0efeae3a7487cf0662b7bee3825752a29/src/test.cpp#L249
        let sk_hex = "4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604";
        let pk_hex = "85695fcbc06cc4c4c9451f4dce21cbf8de3e5a13bf48f44cdbb18e2038ba7b8bb1632d7911ef1e2e08749bddbf165352";
        let sk_vec = hex::decode(sk_hex)?;
        let mut sk_bytes = [0u8; SK_SIZE];
        sk_bytes[..SK_SIZE].clone_from_slice(&sk_vec[..SK_SIZE]);
        let sk = SecretKey::from_bytes(sk_bytes).expect("invalid sk bytes");
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_to_hex = &format!("{}", HexFmt(&pk_bytes));
        assert_eq!(pk_to_hex, pk_hex);
        Ok(())
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
    fn vectors_public_key_set_to_from_bytes() -> Result<()> {
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
            let pks_bytes = hex::decode(vector[0])?;
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

        Ok(())
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
        let restored_sk = restored_sk_set.secret_key();
        assert_eq!(sk.to_bytes(), restored_sk.to_bytes());
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
    fn vectors_secret_key_set_to_from_bytes() -> Result<()> {
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
            let sks_bytes = hex::decode(vector[0])?;
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

        Ok(())
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
        // derivation index [0]
        let child0 = sk.derive_child(&[0][..]);
        assert!(child0 != sk);
        // derivation index [0, 0]
        let child00 = sk.derive_child(&[0, 0][..]);
        assert!(child00 != sk);
        assert!(child00 != child0);
        // derivation index [1]
        let child1 = sk.derive_child(&[1][..]);
        assert!(child1 != sk);
        assert!(child1 != child0);
        // derivation index [2]
        let child2 = sk.derive_child(&[2][..]);
        assert!(child2 != sk);
        assert!(child2 != child0);
        assert!(child2 != child1);
        // derivation index [3]
        let child3 = sk.derive_child(&[3][..]);
        assert!(child3 != sk);
        assert!(child3 != child0);
        assert!(child3 != child0);
        assert!(child3 != child1);
        assert!(child3 != child2);
        // very large derivation index can be used, eg 100 bytes
        let index100b = [3u8; 100];
        let child100b = sk.derive_child(&index100b[..]);
        assert!(child100b != sk);
        // derivation index 0
        let child0i = sk.derive_child(0);
        assert!(child0i.0 != FR_ZERO);
        // derivation index 1
        let child1i = sk.derive_child(1);
        assert!(child1i.0 != FR_ONE);
        assert!(child1i.0 != sk.0);
    }

    #[test]
    fn test_derive_child_public_key() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        // the derived keypair is a match
        let child_sk = sk.derive_child(&[0][..]);
        let child_pk = pk.derive_child(&[0][..]);
        assert_eq!(child_pk, child_sk.public_key());
    }

    #[test]
    fn test_derive_child_key_vectors() -> Result<()> {
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
                "2125994b85332e1478e7d01b81f30933e92074ff05c873ee8306a43dd5be17d4",
                // child public key at random index
                "a01044f663a75c2000c4b33cec26c92e35c56bb77ed4dc1c1bfe88c890df9caf9153b7069dcf1d93c934ccf391fca3a1",
            ],
            vec![
                // secret key
                "0000000000000000000000000000000000000000000000000000000000000003",
                // public key
                "89ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224",
                // index 0
                "00",
                // child secret key at index 0
                "67b1bb08bee06eaa528d1a412d2d4237daa1204234543f27e0afe901a520b78e",
                // child public key at index 0
                "842de40cbb1d66e60b5e4ce3ce02e6081d5fdacf3dbd1cb0c5959c306d54cab40622c5188f4fa91c818c1a5560bcbcc1",
                // index 1
                "01",
                // child secret key at index 1
                "379446550d351164cf5a8ed4f6ad4cb7cab5c7c3388f103515b84e40aaa1ef30",
                // child public key at index 1
                "aecea20ec775b2fd9640517fa4da8e845217f1b4667ace6e7340d1b35ef986c1603056b4a6a66bebe5d2b5a86ff5a7b5",
                // index 2
                "02",
                // child secret key at index 2
                "1ac3cee2dca114a3d0003e6bcf0ac2da26ec2b28044da4bc550a655b527b4693",
                // child public key at index 2
                "8c9c00407c09dcc6ea186fd8d5e6a39018c83b95ff5610307b6e6b186d00ab925b82405adb120e9c3498b8581a282672",
                // index 1 with left padding
                // different to single byte index "01"
                "0000000000000000000000000000000000000000000000000000000000000001",
                // child secret key for 1 with left padding
                "41308f892e28336c5cbf3109c0a6717e759a68badd217e2816b02acc68a852ad",
                // child public key for 1 with left padding
                "a1be856a26d993fee069481b37b22fd4955fcc5cb289bb30f4c6e98d9c36fd6892c7d36674d400c4bda136f9b7c6e1dc",
                // index 1 with right padding
                // different to single byte index "01"
                "0100000000000000000000000000000000000000000000000000000000000000",
                // child secret key for 1 with right padding
                "48c9761c4350e2cf76a765b7d95e6021902d5daf3221cfe2d687ae3e9fba3717",
                // child public key for 1 with right padding
                "a6b1df11c4346da734253993e329ed54ad99907024f35e555374d46b33fb602790105479e68e0d89c48c3798aecc871b",
                // index with 17 bytes
                "0000000000000000000000000000000101",
                // child secret key for 17 bytes
                "120fb53090d6cfd1528c83e83af582f96dd105b43f6622df6d797b174429c0f4",
                // child public key for 17 bytes
                "8c6a3c63379c0c48e652ad3190205ec39e6d0679cf47abca5b92915319ecb5f1eda560801e0490aa6f6566b55e132744",
                // large index greater than q
                "fedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedc",
                // child secret key at large index
                "2ffa71ee5cf75392ffcde2ce8d68fb4524453f55ba2e148d0d4a4000da876be6",
                // child public key at large index
                "b492577c7a7e324dec2e34397689e41fa8a894890db931fe93cdb29c5342e1e50ea53c969fae1780677ab27c4ff62fca",
                // index with more than 256 bits
                // note different to single byte index "00"
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                // child secret key for index more than 256 bits
                "10ca7b3cb66ce637d1de47d25cb6817c4b16efcb2221fc60f0190231b2ad656f",
                // child public key for index more than 256 bits
                "8b1d9fada310a22ec2523e42fa1ece8e6bf5b6bc91e591d352dbe96271a9ba9dbecd9a4529befffaf8e57bf929aa227c",
                // index with child secret key leading zero
                "000000000000002b",
                // child secret key for sk leading zero
                "00cb16c2e0affce5d286c70e980b914c3c48f265c2d526fcdd6128e94799ec8e",
                // child public key for sk leading zero
                "8c13f829f562794c85ac6b145201d364a69b7f76f7e0eef3d3fa9d446757efae575900564ed0cd46c7d6d3a997cf65de",
                // index with child public key trailing zero
                "000000000000006a",
                // child secret key for child pk trailing zero
                "3b754c18e315f1eea4eedcd6ba78997572ed5a389afdf4180da1de78e32943ac",
                // child public key for child pk trailing zero
                "8ab4c8163cf2c7d230f3f45c424272e0e83b7ca251b7481312ae7745c584234e5138e9d071c273c8a433c9657a681400",
            ],
        ];
        for vector in vectors {
            // get parent keypair
            let sk_vec = hex::decode(vector[0])?;
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
                let index = hex::decode(vector[v])?;
                // derive child secret key at this index
                let sk_child = sk.derive_child(&index[..]);
                let sk_child_hex = &format!("{}", HexFmt(&sk_child.to_bytes()));
                assert_eq!(sk_child_hex, vector[v + 1]);
                // derive child public key at this index
                let pk_child = pk.derive_child(&index[..]);
                let pk_child_hex = &format!("{}", HexFmt(&pk_child.to_bytes()));
                assert_eq!(pk_child_hex, vector[v + 2]);
                // confirm these keys are a pair
                assert_eq!(sk_child.public_key(), pk_child);
            }
        }

        Ok(())
    }

    #[test]
    fn test_ciphertext_vectors() -> Result<()> {
        let vectors = vec![
            // Plain old ciphertext
            vec![
                // secret key
                "09f82926174f2fb52fc3674822497362df34186b4cac60ab531d81ac36144b63",
                // plain text hex
                "0102030405",
                // ciphertext
                "9369436c4f3b930aebeb1458b5478a393c90c51de74ebe0ad53b178f25ea0ab51b8acae9847ca3ec9d85bea816e174ca81a7160b714ed5a2a2b6d473473e02345bdeabddad35f13127259b905a8b01ea8225a9449ead9922d8d388959d712bc719889f12f8f273c530e1a7b38a0c2bda9a568453e011c41bb3c66e6dc6c313451802bade49a97e2315507e9a68f1f8794cda1b5420",
            ],
            // Leading zeros and trailing
            vec![
                // secret key
                "0055555555555555555555555555555555555555555555555555555555555500",
                // plain text hex
                "00bdc600",
                // ciphertext with u and w having trailing zeros
                "8d86c6a960cf15f0170b855f5b8d7eca52885fa63ba9c242e54f9cdd5a91f0e42c5b16d39108457613eff00e50b21357af578a279b048d4334434402c129c7754b6461bf653bf57b4b09eb06f53b9360b52438cb9c32c580d9b58981dbf1671519f413245fc288f973d7a47ceca5a21d3e69de7561f70c1c4296f40cdcc0043f20b13e6953fbb1b3363af011350e315fed74a849",
            ],
        ];
        for vector in vectors {
            // get secret key
            let sk_vec =
                hex::decode(vector[0]).map_err(|err| eyre!("invalid msg hex bytes: {}", err))?;
            let mut sk_bytes = [0u8; SK_SIZE];
            sk_bytes[..SK_SIZE].clone_from_slice(&sk_vec[..SK_SIZE]);
            let sk = SecretKey::from_bytes(sk_bytes)
                .map_err(|err| eyre!("invalid secret key bytes: {}", err))?;
            // get ciphertext
            let ct_vec =
                hex::decode(vector[2]).map_err(|err| eyre!("invalid msg hex bytes: {}", err))?;
            let ct = Ciphertext::from_bytes(&ct_vec)
                .map_err(|err| eyre!("invalid ciphertext bytes: {}", err))?;
            // check the ciphertext is valid
            assert!(ct.verify());
            // check the decrypted ciphertext matches the original message
            let msg_vec =
                hex::decode(vector[1]).map_err(|err| eyre!("invalid msg hex bytes: {}", err))?;
            let plaintext = sk.decrypt(&ct).ok_or_else(|| eyre!("decryption failed"))?;
            assert_eq!(plaintext, msg_vec);
        }

        Ok(())
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
        let msk_child = msk.derive_child(&index[..]);
        assert_ne!(msk, msk_child);
        let sks_child = sks.derive_child(&index[..]);
        assert_ne!(sks.to_bytes(), sks_child.to_bytes());
        let sks_child_master = sks_child.secret_key();
        assert_eq!(msk_child, sks_child_master);
        // secret key shares are matching
        // sks.child(x).share(y) == sks.share(y).child(x)
        let sks_share0 = sks.secret_key_share(0);
        let sks_share0_child = sks_share0.derive_child(&index[..]);
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
        let mpk_child = mpk.derive_child(&index[..]);
        assert_ne!(mpk, mpk_child);
        let pks_child = pks.derive_child(&index[..]);
        assert_ne!(pks.to_bytes(), pks_child.to_bytes());
        let pks_child_master = pks_child.public_key();
        assert_eq!(mpk_child, pks_child_master);
        // public key shares are matching
        // pks.child(x).share(y) == pks.share(y).child(x)
        let pks_share0 = pks.public_key_share(0);
        let pks_share0_child = pks_share0.derive_child(&index[..]);
        let pks_child_share0 = pks_child.public_key_share(0);
        assert_eq!(pks_share0_child, pks_child_share0);
        // derived master public key is a pair for derived master secret key
        let sks_child = sks.derive_child(&index[..]);
        assert_eq!(sks_child.secret_key().public_key(), pks_child.public_key());
    }

    #[test]
    fn test_sk_set_child_sig() -> Result<()> {
        // combining signatures from child keyshares produces
        // a valid signature for the child public key set
        let mut rng = rand::thread_rng();
        // The threshold is 3, so 4 signature shares will suffice to decrypt.
        let sks = SecretKeySet::random(3, &mut rng);
        let share_indexes = vec![5u64, 8, 7, 10];
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
                let child_key_share = key_share.derive_child(&index[..]);
                (i, child_key_share)
            })
            .collect();
        // all participants sign a message with their child keyshare
        let msg = "Totally real news";
        let mut child_sig_shares = BTreeMap::default();
        for (i, child_key_share) in child_key_shares.iter() {
            let child_sig_share = child_key_share.sign(&msg);
            child_sig_shares.insert(i, child_sig_share);
        }
        // Combining the child shares creates a valid signature for the child
        // public key set.
        let pks_child = pks.derive_child(&index[..]);
        let sig = pks_child
            .combine_signatures(&child_sig_shares)
            .map_err(|err| eyre!("signatures match: {}", err))?;
        assert!(pks_child.public_key().verify(&sig, msg));

        Ok(())
    }

    #[test]
    fn test_sign_g2_verify_g2() {
        let mut skb = [0u8; 32];
        skb[0] = 0x73;
        let sk = SecretKey::from_bytes(skb).expect("Invalid secret key bytes");
        let msg = b"my message";
        let g2 = hash_g2(msg);
        let sig = sk.sign_g2(&g2);
        let pk = sk.public_key();
        assert!(pk.verify(&sig, msg));
        assert!(pk.verify_g2(&sig, &g2));
    }

    #[test]
    fn test_blind_signature() {
        // c_X is client-side data
        // a_X is authority-side data
        // w_X is bytes that go on the wire
        let mut rng = rand::thread_rng();
        let a_sk = SecretKey::random();
        let a_pk = a_sk.public_key();
        let c_msg = b"Meet at dawn";
        // the client creates a blinded message
        let c_blinding_factor = fr_random(&mut rng);
        let c_blinded_msg = blind_message(c_msg, &c_blinding_factor);
        // the blinded message is sent to the authority for signing
        let w_blinded_msg = c_blinded_msg.to_bytes();
        let a_blinded_msg =
            BlindedMessage::from_bytes(w_blinded_msg).expect("Invalid blinded message");
        assert_eq!(c_blinded_msg, a_blinded_msg);
        // the authority signs the blinded message
        let a_blind_sig = a_sk.sign_g2(&a_blinded_msg.0);
        // the authority sends the blind signature back to the client.
        let w_blind_sig = a_blind_sig.to_bytes();
        let c_blind_sig = Signature::from_bytes(w_blind_sig).expect("Invalid signature");
        assert_eq!(a_blind_sig, c_blind_sig);
        // the client can verify the blinded message was signed correctly, but
        // this is usually not necessary since the unblinded signature is all
        // that will ever be used.
        assert!(a_pk.verify_g2(&c_blind_sig, &c_blinded_msg.0));
        // The blind signature is unblinded by the client.
        let a_sig = unblind_signature(&a_blind_sig, &c_blinding_factor);
        // the client can verify the authority has signed the original message
        assert!(a_pk.verify(&a_sig, c_msg));
        // the authority has not signed any message other than the original one
        let bad_msg = b"Meet at noon";
        assert!(!a_pk.verify(&a_sig, bad_msg));
        // only the original client blinding factor can unblind the signature
        let bad_blinding_factor = fr_random(&mut rng);
        let bad_sig = unblind_signature(&a_blind_sig, &bad_blinding_factor);
        assert!(!a_pk.verify(&bad_sig, c_msg));
    }

    #[test]
    fn test_threshold_blind_sig() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();

        let msg = "Totally real news";
        let blinding_factor = fr_random(&mut rng);
        let blinded_msg = blind_message(msg, &blinding_factor);

        // The threshold is 3, so 4 signature shares will suffice to recreate the share.
        // note: this tests passing a Vec to ::combine_signatures (instead of BTreeMap)
        let blind_sigs: Vec<(_, _)> = [5, 8, 7, 10]
            .iter()
            .map(|&i| {
                let blind_sig = sk_set.secret_key_share(i).sign_g2(&blinded_msg.0);
                (i, blind_sig)
            })
            .collect();

        // Scenario A
        // Combine then unblind; produces a signature matching the main public
        // key.
        // On CPU-bound services it's best to combine-then-unblind since it's
        // less total operations.
        let blind_sig_a = pk_set
            .combine_signatures(blind_sigs.clone())
            .expect("signatures match");
        let sig_a = unblind_signature(&blind_sig_a, &blinding_factor);
        assert!(pk_set.public_key().verify(&sig_a, msg));

        // Scenario B
        // Unblind then combine; produces a signature matching the main public
        // key.
        // On latency-bound services it's best to unblind-then-combine since
        // it removes the unblinding step at the end. Spare cpu may as well be
        // put to use doing 'exessive' unblinding while other signatures are
        // arriving.
        let sigs_b: BTreeMap<_, _> = blind_sigs
            .iter()
            .map(|(i, blind_sig)| {
                let sig = unblind_signature(&blind_sig.0, &blinding_factor);
                (i, SignatureShare(sig))
            })
            .collect();
        let sig_b = pk_set.combine_signatures(sigs_b).expect("signatures match");
        assert!(pk_set.public_key().verify(&sig_b, msg));
        assert_eq!(sig_a, sig_b);

        // Scenario C
        // A different set of signatories produces the same signature.
        let blind_sigs_c: BTreeMap<_, _> = [42, 43, 44, 45]
            .iter()
            .map(|&i| {
                let blind_sig = sk_set.secret_key_share(i).sign_g2(&blinded_msg.0);
                (i, blind_sig)
            })
            .collect();
        let blind_sig_c = pk_set
            .combine_signatures(&blind_sigs_c)
            .expect("signatures match");
        let sig_c = unblind_signature(&blind_sig_c, &blinding_factor);
        assert!(pk_set.public_key().verify(&sig_c, msg));
        assert_eq!(sig_a, sig_c);
    }
}
