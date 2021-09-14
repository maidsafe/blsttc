//! Utilities for distributed key generation: uni- and bivariate polynomials and commitments.
//!
//! If `G` is a group of prime order `r` (written additively), and `g` is a generator, then
//! multiplication by integers factors through `r`, so the map `x -> x * g` (the sum of `x`
//! copies of `g`) is a homomorphism from the field `Fr` of integers modulo `r` to `G`. If the
//! _discrete logarithm_ is hard, i.e. it is infeasible to reverse this map, then `x * g` can be
//! considered a _commitment_ to `x`: By publishing it, you can guarantee to others that you won't
//! change your mind about the value `x`, without revealing it.
//!
//! This concept extends to polynomials: If you have a polynomial `f` over `Fr`, defined as
//! `a * X * X + b * X + c`, you can publish `a * g`, `b * g` and `c * g`. Then others will be able
//! to verify any single value `f(x)` of the polynomial without learning the original polynomial,
//! because `f(x) * g == x * x * (a * g) + x * (b * g) + (c * g)`. Only after learning three (in
//! general `degree + 1`) values, they can interpolate `f` itself.
//!
//! This module defines univariate polynomials (in one variable) and _symmetric_ bivariate
//! polynomials (in two variables) over a field `Fr`, as well as their _commitments_ in `G`.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::iter::repeat_with;
use std::{cmp, iter, ops};

use ff::Field;
use group::{CurveAffine, CurveProjective};
use rand::Rng;
use zeroize::Zeroize;

use crate::cmp_pairing::cmp_projective;
use crate::convert::{fr_from_be_bytes, fr_to_be_bytes, g1_from_be_bytes};
use crate::error::{Error, Result};
use crate::into_fr::IntoFr;
use crate::secret::clear_fr;
use crate::{Fr, G1Affine, G1, PK_SIZE, SK_SIZE};

/// A univariate polynomial in the prime field.
#[derive(PartialEq, Eq, Clone)]
pub struct Poly {
    /// The coefficients of a polynomial.
    pub(super) coeff: Vec<Fr>,
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        for fr in self.coeff.iter_mut() {
            clear_fr(fr)
        }
    }
}

impl Drop for Poly {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A debug statement where the `coeff` vector of prime field elements has been redacted.
impl Debug for Poly {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Poly").field("coeff", &"...").finish()
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl<B: Borrow<Poly>> ops::AddAssign<B> for Poly {
    fn add_assign(&mut self, rhs: B) {
        let len = self.coeff.len();
        let rhs_len = rhs.borrow().coeff.len();
        if rhs_len > len {
            self.coeff.resize(rhs_len, Fr::zero());
        }
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            Field::add_assign(self_c, rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Poly>> ops::Add<B> for &'a Poly {
    type Output = Poly;

    fn add(self, rhs: B) -> Poly {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Poly>> ops::Add<B> for Poly {
    type Output = Poly;

    fn add(mut self, rhs: B) -> Poly {
        self += rhs;
        self
    }
}

impl<'a> ops::Add<Fr> for Poly {
    type Output = Poly;

    fn add(mut self, rhs: Fr) -> Self::Output {
        if self.is_zero() && !rhs.is_zero() {
            self.coeff.push(rhs);
        } else {
            self.coeff[0].add_assign(&rhs);
            self.remove_zeros();
        }
        self
    }
}

impl<'a> ops::Add<u64> for Poly {
    type Output = Poly;

    fn add(self, rhs: u64) -> Self::Output {
        self + rhs.into_fr()
    }
}

impl<B: Borrow<Poly>> ops::SubAssign<B> for Poly {
    fn sub_assign(&mut self, rhs: B) {
        let len = self.coeff.len();
        let rhs_len = rhs.borrow().coeff.len();
        if rhs_len > len {
            self.coeff.resize(rhs_len, Fr::zero());
        }
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            Field::sub_assign(self_c, rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Poly>> ops::Sub<B> for &'a Poly {
    type Output = Poly;

    fn sub(self, rhs: B) -> Poly {
        (*self).clone() - rhs
    }
}

impl<B: Borrow<Poly>> ops::Sub<B> for Poly {
    type Output = Poly;

    fn sub(mut self, rhs: B) -> Poly {
        self -= rhs;
        self
    }
}

// Clippy thinks using `+` in a `Sub` implementation is suspicious.
#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a> ops::Sub<Fr> for Poly {
    type Output = Poly;

    fn sub(self, mut rhs: Fr) -> Self::Output {
        rhs.negate();
        self + rhs
    }
}

impl<'a> ops::Sub<u64> for Poly {
    type Output = Poly;

    fn sub(self, rhs: u64) -> Self::Output {
        self - rhs.into_fr()
    }
}

// Clippy thinks using any `+` and `-` in a `Mul` implementation is suspicious.
#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, B: Borrow<Poly>> ops::Mul<B> for &'a Poly {
    type Output = Poly;

    fn mul(self, rhs: B) -> Self::Output {
        let rhs = rhs.borrow();
        if rhs.is_zero() || self.is_zero() {
            return Poly::zero();
        }
        let n_coeffs = self.coeff.len() + rhs.coeff.len() - 1;
        let mut coeffs = vec![Fr::zero(); n_coeffs];
        let mut tmp = Fr::zero();
        for (i, ca) in self.coeff.iter().enumerate() {
            for (j, cb) in rhs.coeff.iter().enumerate() {
                tmp = *ca;
                tmp.mul_assign(cb);
                coeffs[i + j].add_assign(&tmp);
            }
        }
        clear_fr(&mut tmp);
        Poly::from(coeffs)
    }
}

impl<B: Borrow<Poly>> ops::Mul<B> for Poly {
    type Output = Poly;

    fn mul(self, rhs: B) -> Self::Output {
        &self * rhs
    }
}

impl<B: Borrow<Self>> ops::MulAssign<B> for Poly {
    fn mul_assign(&mut self, rhs: B) {
        *self = &*self * rhs;
    }
}

impl ops::MulAssign<Fr> for Poly {
    fn mul_assign(&mut self, rhs: Fr) {
        if rhs.is_zero() {
            self.zeroize();
            self.coeff.clear();
        } else {
            for c in &mut self.coeff {
                Field::mul_assign(c, &rhs);
            }
        }
    }
}

impl<'a> ops::Mul<&'a Fr> for Poly {
    type Output = Poly;

    fn mul(mut self, rhs: &Fr) -> Self::Output {
        if rhs.is_zero() {
            self.zeroize();
            self.coeff.clear();
        } else {
            self.coeff.iter_mut().for_each(|c| c.mul_assign(rhs));
        }
        self
    }
}

impl ops::Mul<Fr> for Poly {
    type Output = Poly;

    fn mul(self, rhs: Fr) -> Self::Output {
        let rhs = &rhs;
        self * rhs
    }
}

impl<'a> ops::Mul<&'a Fr> for &'a Poly {
    type Output = Poly;

    fn mul(self, rhs: &Fr) -> Self::Output {
        (*self).clone() * rhs
    }
}

impl<'a> ops::Mul<Fr> for &'a Poly {
    type Output = Poly;

    fn mul(self, rhs: Fr) -> Self::Output {
        (*self).clone() * rhs
    }
}

impl ops::Mul<u64> for Poly {
    type Output = Poly;

    fn mul(self, rhs: u64) -> Self::Output {
        self * rhs.into_fr()
    }
}

/// Creates a new `Poly` instance from a vector of prime field elements representing the
/// coefficients of the polynomial.
impl From<Vec<Fr>> for Poly {
    fn from(coeff: Vec<Fr>) -> Self {
        Poly { coeff }
    }
}

impl Poly {
    /// Creates a random polynomial.
    ///
    /// # Panics
    ///
    /// Panics if the `degree` is too large for the coefficients to fit into a `Vec`.
    pub fn random<R: Rng>(degree: usize, rng: &mut R) -> Self {
        Poly::try_random(degree, rng)
            .unwrap_or_else(|e| panic!("Failed to create random `Poly`: {}", e))
    }

    /// Creates a random polynomial. This constructor is identical to the `Poly::random()`
    /// constructor in every way except that this constructor will return an `Err` where
    /// `try_random` would return an error.
    pub fn try_random<R: Rng>(degree: usize, rng: &mut R) -> Result<Self> {
        if degree == usize::max_value() {
            return Err(Error::DegreeTooHigh);
        }
        let coeff: Vec<Fr> = repeat_with(|| Fr::random(rng)).take(degree + 1).collect();
        Ok(Poly::from(coeff))
    }

    /// Returns the polynomial with constant value `0`.
    pub fn zero() -> Self {
        Poly { coeff: vec![] }
    }

    /// Returns `true` if the polynomial is the constant value `0`.
    pub fn is_zero(&self) -> bool {
        self.coeff.iter().all(|coeff| coeff.is_zero())
    }

    /// Returns the polynomial with constant value `1`.
    pub fn one() -> Self {
        Poly::constant(Fr::one())
    }

    /// Returns the polynomial with constant value `c`.
    pub fn constant(mut c: Fr) -> Self {
        // We create a raw pointer to the field element within this method's stack frame so we can
        // overwrite that portion of memory with zeros once we have copied the element onto the
        // heap as part of the vector of polynomial coefficients.
        let poly = Poly::from(vec![c]);
        clear_fr(&mut c);
        poly
    }

    /// Returns the identity function, i.e. the polynomial "`x`".
    pub fn identity() -> Self {
        Poly::monomial(1)
    }

    /// Returns the (monic) monomial: `x.pow(degree)`.
    pub fn monomial(degree: usize) -> Self {
        let coeff: Vec<Fr> = iter::repeat(Fr::zero())
            .take(degree)
            .chain(iter::once(Fr::one()))
            .collect();
        Poly::from(coeff)
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    pub fn interpolate<T, U, I>(samples_repr: I) -> Self
    where
        I: IntoIterator<Item = (T, U)>,
        T: IntoFr,
        U: IntoFr,
    {
        let convert = |(x, y): (T, U)| (x.into_fr(), y.into_fr());
        let samples: Vec<(Fr, Fr)> = samples_repr.into_iter().map(convert).collect();
        Poly::compute_interpolation(&samples)
    }

    /// Returns the degree.
    pub fn degree(&self) -> usize {
        self.coeff.len().saturating_sub(1)
    }

    /// Returns the value at the point `i`.
    pub fn evaluate<T: IntoFr>(&self, i: T) -> Fr {
        let mut result = match self.coeff.last() {
            None => return Fr::zero(),
            Some(c) => *c,
        };
        let x = i.into_fr();
        for c in self.coeff.iter().rev().skip(1) {
            result.mul_assign(&x);
            result.add_assign(c);
        }
        result
    }

    /// Returns the corresponding commitment.
    pub fn commitment(&self) -> Commitment {
        let to_g1 = |c: &Fr| G1Affine::one().mul(*c);
        Commitment {
            coeff: self.coeff.iter().map(to_g1).collect(),
        }
    }

    /// Serializes to big endian bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let coeff_size = self.coeff.len();
        let bytes_size = coeff_size * SK_SIZE;
        let mut poly_bytes = vec![0; bytes_size];
        for i in 0..coeff_size {
            let fr = self.coeff[i];
            let fr_bytes = fr_to_be_bytes(fr);
            let fr_size = fr_bytes.len();
            for j in 0..fr_size {
                poly_bytes[i * SK_SIZE + j] = fr_bytes[j];
            }
        }
        poly_bytes
    }

    /// Deserializes from big endian bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let mut c: Vec<Fr> = vec![];
        let coeff_size = bytes.len() / SK_SIZE;
        for i in 0..coeff_size {
            let mut fr_bytes = [0u8; SK_SIZE];
            for j in 0..SK_SIZE {
                fr_bytes[j] = bytes[i * SK_SIZE + j];
            }
            let fr = fr_from_be_bytes(fr_bytes)?;
            c.push(fr);
        }
        Ok(Poly { coeff: c })
    }

    /// Removes all trailing zero coefficients.
    fn remove_zeros(&mut self) {
        let zeros = self.coeff.iter().rev().take_while(|c| c.is_zero()).count();
        let len = self.coeff.len() - zeros;
        self.coeff.truncate(len);
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    fn compute_interpolation(samples: &[(Fr, Fr)]) -> Self {
        if samples.is_empty() {
            return Poly::zero();
        }
        // Interpolates on the first `i` samples.
        let mut poly = Poly::constant(samples[0].1);
        let mut minus_s0 = samples[0].0;
        minus_s0.negate();
        // Is zero on the first `i` samples.
        let mut base = Poly::from(vec![minus_s0, Fr::one()]);

        // We update `base` so that it is always zero on all previous samples, and `poly` so that
        // it has the correct values on the previous samples.
        for (ref x, ref y) in &samples[1..] {
            // Scale `base` so that its value at `x` is the difference between `y` and `poly`'s
            // current value at `x`: Adding it to `poly` will then make it correct for `x`.
            let mut diff = *y;
            diff.sub_assign(&poly.evaluate(x));
            let base_val = base.evaluate(x);
            diff.mul_assign(&base_val.inverse().expect("sample points must be distinct"));
            base *= diff;
            poly += &base;

            // Finally, multiply `base` by X - x, so that it is zero at `x`, too, now.
            let mut minus_x = *x;
            minus_x.negate();
            base *= Poly::from(vec![minus_x, Fr::one()]);
        }
        poly
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field elements.
    pub fn reveal(&self) -> String {
        format!("Poly {{ coeff: {:?} }}", self.coeff)
    }
}

/// A commitment to a univariate polynomial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// The coefficients of the polynomial.
    pub(super) coeff: Vec<G1>,
}

/// Creates a new `Commitment` instance
impl From<Vec<G1>> for Commitment {
    fn from(coeff: Vec<G1>) -> Self {
        Commitment { coeff }
    }
}

impl PartialOrd for Commitment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Commitment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.coeff.len().cmp(&other.coeff.len()).then_with(|| {
            self.coeff
                .iter()
                .zip(&other.coeff)
                .find(|(x, y)| x != y)
                .map_or(Ordering::Equal, |(x, y)| cmp_projective(x, y))
        })
    }
}

impl Hash for Commitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.coeff.len().hash(state);
        for c in &self.coeff {
            c.into_affine().into_compressed().as_ref().hash(state);
        }
    }
}

impl<B: Borrow<Commitment>> ops::AddAssign<B> for Commitment {
    fn add_assign(&mut self, rhs: B) {
        let len = cmp::max(self.coeff.len(), rhs.borrow().coeff.len());
        self.coeff.resize(len, G1::zero());
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.add_assign(rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Commitment>> ops::Add<B> for &'a Commitment {
    type Output = Commitment;

    fn add(self, rhs: B) -> Commitment {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Commitment>> ops::Add<B> for Commitment {
    type Output = Commitment;

    fn add(mut self, rhs: B) -> Commitment {
        self += rhs;
        self
    }
}

impl Commitment {
    /// Returns the polynomial's degree.
    pub fn degree(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the `i`-th public key share.
    pub fn evaluate<T: IntoFr>(&self, i: T) -> G1 {
        let mut result = match self.coeff.last() {
            None => return G1::zero(),
            Some(c) => *c,
        };
        let x = i.into_fr();
        for c in self.coeff.iter().rev().skip(1) {
            result.mul_assign(x);
            result.add_assign(c);
        }
        result
    }

    /// Serializes to big endian bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let coeff_size = self.coeff.len();
        let bytes_size = coeff_size * PK_SIZE;
        let mut commit_bytes = vec![0; bytes_size];
        for i in 0..coeff_size {
            let g1 = self.coeff[i];
            let g1_bytes = g1.into_affine().into_compressed().as_ref().to_vec();
            let g1_size = g1_bytes.len();
            for j in 0..g1_size {
                commit_bytes[i * PK_SIZE + j] = g1_bytes[j];
            }
        }
        commit_bytes
    }

    /// Deserializes from big endian bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let mut c: Vec<G1> = vec![];
        let coeff_size = bytes.len() / PK_SIZE;
        for i in 0..coeff_size {
            let mut g1_bytes = [0; PK_SIZE];
            for j in 0..PK_SIZE {
                g1_bytes[j] = bytes[i * PK_SIZE + j];
            }
            let g1 = g1_from_be_bytes(g1_bytes)?;
            c.push(g1);
        }
        Ok(Commitment { coeff: c })
    }

    /// Removes all trailing zero coefficients.
    fn remove_zeros(&mut self) {
        let zeros = self.coeff.iter().rev().take_while(|c| c.is_zero()).count();
        let len = self.coeff.len() - zeros;
        self.coeff.truncate(len)
    }
}

/// A symmetric bivariate polynomial in the prime field.
///
/// This can be used for Verifiable Secret Sharing and Distributed Key Generation. See the module
/// documentation for details.
#[derive(Clone)]
pub struct BivarPoly {
    /// The polynomial's degree in each of the two variables.
    degree: usize,
    /// The coefficients of the polynomial. Coefficient `(i, j)` for `i <= j` is in position
    /// `j * (j + 1) / 2 + i`.
    coeff: Vec<Fr>,
}

impl Zeroize for BivarPoly {
    fn zeroize(&mut self) {
        for fr in self.coeff.iter_mut() {
            clear_fr(fr)
        }
        self.degree.zeroize();
    }
}

impl Drop for BivarPoly {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A debug statement where the `coeff` vector has been redacted.
impl Debug for BivarPoly {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BivarPoly")
            .field("degree", &self.degree)
            .field("coeff", &"...")
            .finish()
    }
}

impl BivarPoly {
    /// Creates a random polynomial.
    ///
    /// # Panics
    ///
    /// Panics if the degree is too high for the coefficients to fit into a `Vec`.
    pub fn random<R: Rng>(degree: usize, rng: &mut R) -> Self {
        BivarPoly::try_random(degree, rng).unwrap_or_else(|e| {
            panic!(
                "Failed to create random `BivarPoly` of degree {}: {}",
                degree, e
            )
        })
    }

    /// Creates a random polynomial.
    pub fn try_random<R: Rng>(degree: usize, rng: &mut R) -> Result<Self> {
        let len = coeff_pos(degree, degree)
            .and_then(|l| l.checked_add(1))
            .ok_or(Error::DegreeTooHigh)?;
        let poly = BivarPoly {
            degree,
            coeff: repeat_with(|| Fr::random(rng)).take(len).collect(),
        };
        Ok(poly)
    }

    /// Returns the polynomial's degree; which is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the polynomial's value at the point `(x, y)`.
    pub fn evaluate<T: IntoFr>(&self, x: T, y: T) -> Fr {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = Fr::zero();
        for (i, x_pow_i) in x_pow.into_iter().enumerate() {
            for (j, y_pow_j) in y_pow.iter().enumerate() {
                let index = coeff_pos(i, j).expect("polynomial degree too high");
                let mut summand = self.coeff[index];
                summand.mul_assign(&x_pow_i);
                summand.mul_assign(y_pow_j);
                result.add_assign(&summand);
            }
        }
        result
    }

    /// Returns the `x`-th row, as a univariate polynomial.
    pub fn row<T: IntoFr>(&self, x: T) -> Poly {
        let x_pow = self.powers(x);
        let coeff: Vec<Fr> = (0..=self.degree)
            .map(|i| {
                // TODO: clear these secrets from the stack.
                let mut result = Fr::zero();
                for (j, x_pow_j) in x_pow.iter().enumerate() {
                    let index = coeff_pos(i, j).expect("polynomial degree too high");
                    let mut summand = self.coeff[index];
                    summand.mul_assign(x_pow_j);
                    result.add_assign(&summand);
                }
                result
            })
            .collect();
        Poly::from(coeff)
    }

    /// Returns the corresponding commitment. That information can be shared publicly.
    pub fn commitment(&self) -> BivarCommitment {
        let to_pub = |c: &Fr| G1Affine::one().mul(*c);
        BivarCommitment {
            degree: self.degree,
            coeff: self.coeff.iter().map(to_pub).collect(),
        }
    }

    /// Returns the `0`-th to `degree`-th power of `x`.
    fn powers<T: IntoFr>(&self, x: T) -> Vec<Fr> {
        powers(x, self.degree)
    }

    /// Generates a non-redacted debug string. This method differs from the
    /// `Debug` implementation in that it *does* leak the the struct's
    /// internal state.
    pub fn reveal(&self) -> String {
        format!(
            "BivarPoly {{ degree: {}, coeff: {:?} }}",
            self.degree, self.coeff
        )
    }

    /// Serializes to big endian bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let coeff_size = self.coeff.len();
        let bytes_size = coeff_size * SK_SIZE;
        let mut poly_bytes = vec![0; bytes_size];
        for i in 0..coeff_size {
            let fr = self.coeff[i];
            let fr_bytes = fr_to_be_bytes(fr);
            let fr_size = fr_bytes.len();
            for j in 0..fr_size {
                poly_bytes[i * SK_SIZE + j] = fr_bytes[j];
            }
        }
        poly_bytes
    }

    /// Deserializes from big endian bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let mut c: Vec<Fr> = vec![];
        let coeff_size = bytes.len() / SK_SIZE;
        for coeff_index in 0..coeff_size {
            // get the Fr for this coeff
            let mut fr_bytes = [0u8; SK_SIZE];
            for i in 0..SK_SIZE {
                fr_bytes[i] = bytes[coeff_index * SK_SIZE + i];
            }
            let fr = fr_from_be_bytes(fr_bytes)?;
            c.push(fr);
        }
        let d = ((2 * coeff_size) as f64).sqrt() as usize - 1;
        Ok(BivarPoly {
            degree: d,
            coeff: c,
        })
    }
}

/// A commitment to a symmetric bivariate polynomial.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BivarCommitment {
    /// The polynomial's degree in each of the two variables.
    pub(crate) degree: usize,
    /// The commitments to the coefficients.
    pub(crate) coeff: Vec<G1>,
}

impl Hash for BivarCommitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.degree.hash(state);
        for c in &self.coeff {
            c.into_affine().into_compressed().as_ref().hash(state);
        }
    }
}

impl PartialOrd for BivarCommitment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BivarCommitment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.degree.cmp(&other.degree).then_with(|| {
            self.coeff
                .iter()
                .zip(&other.coeff)
                .find(|(x, y)| x != y)
                .map_or(Ordering::Equal, |(x, y)| cmp_projective(x, y))
        })
    }
}

impl BivarCommitment {
    /// Returns the polynomial's degree: It is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the commitment's value at the point `(x, y)`.
    pub fn evaluate<T: IntoFr>(&self, x: T, y: T) -> G1 {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = G1::zero();
        for (i, x_pow_i) in x_pow.into_iter().enumerate() {
            for (j, y_pow_j) in y_pow.iter().enumerate() {
                let index = coeff_pos(i, j).expect("polynomial degree too high");
                let mut summand = self.coeff[index];
                summand.mul_assign(x_pow_i);
                summand.mul_assign(*y_pow_j);
                result.add_assign(&summand);
            }
        }
        result
    }

    /// Returns the `x`-th row, as a commitment to a univariate polynomial.
    pub fn row<T: IntoFr>(&self, x: T) -> Commitment {
        let x_pow = self.powers(x);
        let coeff: Vec<G1> = (0..=self.degree)
            .map(|i| {
                let mut result = G1::zero();
                for (j, x_pow_j) in x_pow.iter().enumerate() {
                    let index = coeff_pos(i, j).expect("polynomial degree too high");
                    let mut summand = self.coeff[index];
                    summand.mul_assign(*x_pow_j);
                    result.add_assign(&summand);
                }
                result
            })
            .collect();
        Commitment { coeff }
    }

    /// Returns the `0`-th to `degree`-th power of `x`.
    fn powers<T: IntoFr>(&self, x: T) -> Vec<Fr> {
        powers(x, self.degree)
    }

    /// Serializes to big endian bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let coeff_size = self.coeff.len();
        let bytes_size = coeff_size * PK_SIZE;
        let mut commit_bytes = vec![0; bytes_size];
        for i in 0..coeff_size {
            let g1 = self.coeff[i];
            let g1_bytes = g1.into_affine().into_compressed().as_ref().to_vec();
            let g1_size = g1_bytes.len();
            // TODO if not equal then should do padding instead of fail?
            assert_eq!(g1_size, PK_SIZE);
            for j in 0..g1_size {
                commit_bytes[i * PK_SIZE + j] = g1_bytes[j];
            }
        }
        commit_bytes
    }

    /// Deserializes from big endian bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let mut c: Vec<G1> = vec![];
        let coeff_size = bytes.len() / PK_SIZE;
        for i in 0..coeff_size {
            let mut g1_bytes = [0; PK_SIZE];
            for j in 0..PK_SIZE {
                g1_bytes[j] = bytes[i * PK_SIZE + j];
            }
            let g1 = g1_from_be_bytes(g1_bytes)?;
            c.push(g1);
        }
        let d = ((2 * coeff_size) as f64).sqrt() as usize - 1;
        Ok(BivarCommitment {
            degree: d,
            coeff: c,
        })
    }
}

/// Returns the `0`-th to `degree`-th power of `x`.
fn powers<T: IntoFr>(into_x: T, degree: usize) -> Vec<Fr> {
    let x = into_x.into_fr();
    let mut x_pow_i = Fr::one();
    iter::once(x_pow_i)
        .chain((0..degree).map(|_| {
            x_pow_i.mul_assign(&x);
            x_pow_i
        }))
        .collect()
}

/// Returns the position of coefficient `(i, j)` in the vector describing a symmetric bivariate
/// polynomial. If `i` or `j` are too large to represent the position as a `usize`, `None` is
/// returned.
pub(crate) fn coeff_pos(i: usize, j: usize) -> Option<usize> {
    // Since the polynomial is symmetric, we can order such that `j >= i`.
    let (j, i) = if j >= i { (j, i) } else { (i, j) };
    i.checked_add(j.checked_mul(j.checked_add(1)?)? / 2)
}

#[cfg(test)]
mod tests {
    use eyre::{eyre, Result};
    use std::collections::BTreeMap;

    use super::fr_to_be_bytes;
    use super::{coeff_pos, BivarCommitment, BivarPoly, Commitment, IntoFr, Poly};
    use super::{Fr, G1Affine, G1};
    use super::{PK_SIZE, SK_SIZE};
    use ff::Field;
    use group::{CurveAffine, CurveProjective};
    use hex_fmt::HexFmt;
    use zeroize::Zeroize;

    #[test]
    fn test_coeff_pos() {
        let mut i = 0;
        let mut j = 0;
        for n in 0..100 {
            assert_eq!(Some(n), coeff_pos(i, j));
            if i >= j {
                j += 1;
                i = 0;
            } else {
                i += 1;
            }
        }
        let too_large = 1 << (0usize.count_zeros() / 2);
        assert_eq!(None, coeff_pos(0, too_large));
    }

    #[test]
    fn poly() {
        // The polynomial 5 X³ + X - 2.
        let x_pow_3 = Poly::monomial(3);
        let x_pow_1 = Poly::monomial(1);
        let poly = x_pow_3 * 5 + x_pow_1 - 2;

        let coeff: Vec<_> = [-2, 1, 0, 5].iter().map(IntoFr::into_fr).collect();
        assert_eq!(Poly { coeff }, poly);
        let samples = vec![(-1, -8), (2, 40), (3, 136), (5, 628)];
        for &(x, y) in &samples {
            assert_eq!(y.into_fr(), poly.evaluate(x));
        }
        let interp = Poly::interpolate(samples);
        assert_eq!(interp, poly);
    }

    #[test]
    fn test_zeroize() {
        let mut poly = Poly::monomial(3) + Poly::monomial(2) - 1;
        poly.zeroize();
        assert!(poly.is_zero());

        let mut bi_poly = BivarPoly::random(3, &mut rand::thread_rng());
        let random_commitment = bi_poly.commitment();

        bi_poly.zeroize();

        let zero_commitment = bi_poly.commitment();
        assert_ne!(random_commitment, zero_commitment);

        let mut rng = rand::thread_rng();
        let (x, y): (Fr, Fr) = (Fr::random(&mut rng), Fr::random(&mut rng));
        assert_eq!(zero_commitment.evaluate(x, y), G1::zero());
    }

    #[test]
    fn distributed_key_generation() {
        let mut rng = rand::thread_rng();
        let dealer_num = 3;
        let node_num = 5;
        let faulty_num = 2;

        // For distributed key generation, a number of dealers, only one of who needs to be honest,
        // generates random bivariate polynomials and publicly commits to them. In practice, the
        // dealers can e.g. be any `faulty_num + 1` nodes.
        let bi_polys: Vec<BivarPoly> = (0..dealer_num)
            .map(|_| BivarPoly::random(faulty_num, &mut rng))
            .collect();
        let pub_bi_commits: Vec<_> = bi_polys.iter().map(BivarPoly::commitment).collect();

        let mut sec_keys = vec![Fr::zero(); node_num];

        // Each dealer sends row `m` to node `m`, where the index starts at `1`. Don't send row `0`
        // to anyone! The nodes verify their rows, and send _value_ `s` on to node `s`. They again
        // verify the values they received, and collect them.
        for (bi_poly, bi_commit) in bi_polys.iter().zip(&pub_bi_commits) {
            for m in 1..=node_num {
                // Node `m` receives its row and verifies it.
                let row_poly = bi_poly.row(m);
                let row_commit = bi_commit.row(m);
                assert_eq!(row_poly.commitment(), row_commit);
                // Node `s` receives the `s`-th value and verifies it.
                for s in 1..=node_num {
                    let val = row_poly.evaluate(s);
                    let val_g1 = G1Affine::one().mul(val);
                    assert_eq!(bi_commit.evaluate(m, s), val_g1);
                    // The node can't verify this directly, but it should have the correct value:
                    assert_eq!(bi_poly.evaluate(m, s), val);
                }

                // A cheating dealer who modified the polynomial would be detected.
                let x_pow_2 = Poly::monomial(2);
                let five = Poly::constant(5.into_fr());
                let wrong_poly = row_poly.clone() + x_pow_2 * five;
                assert_ne!(wrong_poly.commitment(), row_commit);

                // If `2 * faulty_num + 1` nodes confirm that they received a valid row, then at
                // least `faulty_num + 1` honest ones did, and sent the correct values on to node
                // `s`. So every node received at least `faulty_num + 1` correct entries of their
                // column/row (remember that the bivariate polynomial is symmetric). They can
                // reconstruct the full row and in particular value `0` (which no other node knows,
                // only the dealer). E.g. let's say nodes `1`, `2` and `4` are honest. Then node
                // `m` received three correct entries from that row:
                let received: BTreeMap<_, _> = [1, 2, 4]
                    .iter()
                    .map(|&i| (i, bi_poly.evaluate(m, i)))
                    .collect();
                let my_row = Poly::interpolate(received);
                assert_eq!(bi_poly.evaluate(m, 0), my_row.evaluate(0));
                assert_eq!(row_poly, my_row);

                // The node sums up all values number `0` it received from the different dealer. No
                // dealer and no other node knows the sum in the end.
                sec_keys[m - 1].add_assign(&my_row.evaluate(Fr::zero()));
            }
        }

        // Each node now adds up all the first values of the rows it received from the different
        // dealers (excluding the dealers where fewer than `2 * faulty_num + 1` nodes confirmed).
        // The whole first column never gets added up in practice, because nobody has all the
        // information. We do it anyway here; entry `0` is the secret key that is not known to
        // anyone, neither a dealer, nor a node:
        let mut sec_key_set = Poly::zero();
        for bi_poly in &bi_polys {
            sec_key_set += bi_poly.row(0);
        }
        for m in 1..=node_num {
            assert_eq!(sec_key_set.evaluate(m), sec_keys[m - 1]);
        }

        // The sum of the first rows of the public commitments is the commitment to the secret key
        // set.
        let mut sum_commit = Poly::zero().commitment();
        for bi_commit in &pub_bi_commits {
            sum_commit += bi_commit.row(0);
        }
        assert_eq!(sum_commit, sec_key_set.commitment());
    }

    #[test]
    fn test_commitment_to_from_bytes() {
        let degree = 3;
        let mut rng = rand::thread_rng();
        let poly = Poly::random(degree, &mut rng);
        let commitment = poly.commitment();
        // length is fixed to (degree + 1) * 48
        let commitment_bytes = commitment.to_bytes();
        assert_eq!(commitment_bytes.len(), (degree + 1) * 48);
        // the first bytes of the commitment match the first G1
        let g1 = commitment.evaluate(0);
        let g1_bytes = g1.into_affine().into_compressed().as_ref().to_vec();
        let g1_bytes_size = g1_bytes.len();
        for i in 0..g1_bytes_size {
            assert_eq!(g1_bytes[i], commitment_bytes[i]);
        }
        // from bytes gives original commitment
        let restored_commitment =
            Commitment::from_bytes(commitment_bytes).expect("invalid commitment bytes");
        assert_eq!(commitment, restored_commitment);
        // for vectors see PublicKeySet
    }

    #[test]
    fn test_bivar_commitment_to_from_bytes() {
        let mut rng = rand::thread_rng();
        let degree = 3;
        let bi_poly = BivarPoly::random(degree, &mut rng);
        let bi_commit = bi_poly.commitment();
        let commitment = bi_commit.row(0);
        // length is fixed by the degree and G1 size
        let bi_commit_bytes = bi_commit.to_bytes();
        let dp1 = degree + 1;
        let sum = dp1 * (dp1 + 1) / 2; // sum 1,2,3,...,dp1
        let expected_size = sum * PK_SIZE;
        assert_eq!(bi_commit_bytes.len(), expected_size);
        // the first bytes of the bivarcommitment match the first commitment public key
        let commitment_bytes = commitment.to_bytes();
        for i in 0..PK_SIZE {
            assert_eq!(commitment_bytes[i], bi_commit_bytes[i]);
        }
        // from_bytes gives original bivar_commitment
        let restored_bi_commit =
            BivarCommitment::from_bytes(bi_commit_bytes).expect("invalid bivar commitment bytes");
        assert_eq!(bi_commit, restored_bi_commit);
        // test rows match
        for i in 0..10 {
            assert_eq!(bi_commit.row(i), restored_bi_commit.row(i));
        }
    }

    #[test]
    fn vectors_bivar_commitment_to_from_bytes() -> Result<()> {
        let vectors = vec![
            // Plain old Bivar Commitment
            vec![
                // bivar commitment
                "84339010af2fa47ebb8294681b2b61d6ec4c0d6ce595c0a8c57234d348c7be120520a6b710f061196d3fa30323e1bcb48ad0b4a8180ff4ca8888f6e8bd869c43c5b111c2733bab514d826bed4ec10f5ca4aacc838c69cba6a99c14cc59646e69ad14932a863413cbb57d3a0aad84d7ec62276a63990d686058c24fef6e0cc17f9360ac4f8e20725bdabd591ad25c4cf98f9fe02f53ef5876dc6744f18f3462e9a5d0a83d30e949acb2e48ba8ee50d3674a7c4b7d75372983c2fd3e9e9291b0e697993cefe339b05133e2ebb51ff3c63e711969c6d0704631059db9a990183aca270acd5fb82ea78bab983c39290b8c71afd930a68bd2a35bd6fd5e7bc09877dfe7dbafd8f953172016da9cd9e816a09677df3a4c8c2339e530acda235f5feefd",
                // commitment row 0
                "84339010af2fa47ebb8294681b2b61d6ec4c0d6ce595c0a8c57234d348c7be120520a6b710f061196d3fa30323e1bcb48ad0b4a8180ff4ca8888f6e8bd869c43c5b111c2733bab514d826bed4ec10f5ca4aacc838c69cba6a99c14cc59646e698f9fe02f53ef5876dc6744f18f3462e9a5d0a83d30e949acb2e48ba8ee50d3674a7c4b7d75372983c2fd3e9e9291b0e6",
                // commitment row 1
                "b9ee0808165ae836d0bf3deeb4e3f3399dde9c6377bf1f0f1dd5096f5f2f61afad3109e9454521832eeac831cad46ef48a0974487ffb0e5343f387e39d5f40312522ca0d90e51d20c89ff7347a724705f8d4429bb6e27100e603195cf89d38a1a4346721f22704f18b2a9fa001944ebe48b8e08eca91c06c23f13061e5929503d67549526591693da175125eb2d17178",
            ]
        ];
        for vector in vectors {
            // read bivar commitment
            let bi_commit_bytes =
                hex::decode(vector[0]).map_err(|err| eyre!("invalid msg hex bytes: {}", err))?;
            let bi_commit = BivarCommitment::from_bytes(bi_commit_bytes)
                .expect("invalid bivar commitment bytes");
            // check row 0
            let row_0 = bi_commit.row(0);
            let row_0_hex = &format!("{}", HexFmt(&row_0.to_bytes()));
            assert_eq!(row_0_hex, vector[1]);
            // check row 1
            let row_1 = bi_commit.row(1);
            let row_1_hex = &format!("{}", HexFmt(&row_1.to_bytes()));
            assert_eq!(row_1_hex, vector[2]);
        }

        Ok(())
    }

    #[test]
    fn test_bivar_commitment_to_from_bytes_large_degree() {
        // The overall size increases rapidly, size is sum(1..degree+1)
        let mut rng = rand::thread_rng();
        let degree = 9; // TODO pick a less magic value here
        let bi_poly = BivarPoly::random(degree, &mut rng);
        let bi_commit = bi_poly.commitment();
        let bi_commit_bytes = bi_commit.to_bytes();
        let dp1 = degree + 1;
        let sum = dp1 * (dp1 + 1) / 2; // sum of 1,2,3,...,dp1
        let expected_size = sum * 48;
        assert_eq!(bi_commit_bytes.len(), expected_size);
    }

    #[test]
    fn test_poly_to_from_bytes() {
        let degree = 3;
        let mut rng = rand::thread_rng();
        let poly = Poly::random(degree, &mut rng);
        // length is fixed to (degree + 1) * 32
        let poly_bytes = poly.to_bytes();
        assert_eq!(poly_bytes.len(), (degree + 1) * 32);
        // the first bytes of the poly match the first Fr
        let fr = poly.evaluate(0);
        let fr_bytes = fr_to_be_bytes(fr);
        let fr_bytes_size = fr_bytes.len();
        for i in 0..fr_bytes_size {
            assert_eq!(fr_bytes[i], poly_bytes[i]);
        }
        // from bytes gives original poly
        let restored_poly = Poly::from_bytes(poly_bytes).expect("invalid poly bytes");
        assert_eq!(poly, restored_poly);
        // for vectors see SecretKeySet
    }

    #[test]
    fn test_bivar_poly_to_from_bytes() {
        let degree = 3;
        let mut rng = rand::thread_rng();
        let bi_poly = BivarPoly::random(degree, &mut rng);
        // length is fixed by the degree and Fr size
        let bi_poly_bytes = bi_poly.to_bytes();
        let dp1 = degree + 1;
        let sum = dp1 * (dp1 + 1) / 2; // sum 1,2,3,...,dp1
        let expected_size = sum * SK_SIZE;
        assert_eq!(bi_poly_bytes.len(), expected_size);
        // the first bytes of the bivarypoly match the first poly
        let poly = bi_poly.row(0);
        let poly_bytes = poly.to_bytes();
        for i in 0..SK_SIZE {
            assert_eq!(poly_bytes[i], bi_poly_bytes[i]);
        }
        // from_bytes gives original bivar_poly
        let restored_bi_poly = BivarPoly::from_bytes(bi_poly_bytes).expect("invalid bipoly bytes");
        // cannot test equality for bi_poly so test using reveal
        assert_eq!(bi_poly.reveal(), restored_bi_poly.reveal());
        // test rows match
        for i in 0..10 {
            assert_eq!(bi_poly.row(i), restored_bi_poly.row(i));
        }
    }

    #[test]
    fn test_bivar_poly_to_from_bytes_large_degree() {
        let mut rng = rand::thread_rng();
        let degree = 9; // TODO pick a less magic value here
        let bi_poly = BivarPoly::random(degree, &mut rng);
        let bi_poly_bytes = bi_poly.to_bytes();
        let dp1 = degree + 1;
        let sum = dp1 * (dp1 + 1) / 2; // sum of 1,2,3,...,dp1
        let expected_size = sum * SK_SIZE;
        assert_eq!(bi_poly_bytes.len(), expected_size);
    }

    #[test]
    fn vectors_bivar_poly_to_from_bytes() -> Result<()> {
        let vectors = vec![
            // Plain old Bivar Poly
            // Sourced from BivarPoly::reveal and Poly::reveal
            vec![
                // bivar poly
                "016088115a0e8748a29b4bd8dd930692b86241405844f0bbd2fcafb6b4f03880222caa92f7eea1dd8a0e4f2d1e62672a5c12dfcb86199515d4a450ed7921d7ca1407dec2b53c472ffcaf4dbfcd8fe5089cb64a7b5ce7e38655aa97400a3bc1bb4045160918bad84c11afc883e514321009a113cb9bc3b7b941486ec3ca4a273565951ee649287a5809bc0036b8ffee73eb51dc4e3f35e7578169e66823da066672c4060b5f46f15eb1a7c253bb564d9ad2e9c12182a0df61499788817d21a133",
                // row 0 poly
                "016088115a0e8748a29b4bd8dd930692b86241405844f0bbd2fcafb6b4f03880222caa92f7eea1dd8a0e4f2d1e62672a5c12dfcb86199515d4a450ed7921d7ca4045160918bad84c11afc883e514321009a113cb9bc3b7b941486ec3ca4a2735",
                // row 1 poly
                "63d248ad6ab801723e596389e1099fcd1e1634d77a223d8ae8e96f67f85c377f27dc00e8ccb5e61d5d3fc51b9b5062a1905d6292223903f4abb8ce96a7379fea30c2ec546def4972669fdafe4626be14206169355d9dc6740c49ddaf6b45cecc",
            ],
        ];
        for vector in vectors {
            // read BivarPoly from hex
            let bi_poly_bytes =
                hex::decode(vector[0]).map_err(|err| eyre!("invalid msg hex bytes: {}", err))?;
            let bi_poly = BivarPoly::from_bytes(bi_poly_bytes).expect("invalid bipoly bytes");
            // check row 0
            let row_0 = bi_poly.row(0);
            let row_0_hex = &format!("{}", HexFmt(&row_0.to_bytes()));
            assert_eq!(row_0_hex, vector[1]);
            // check row 1
            let row_1 = bi_poly.row(1);
            let row_1_hex = &format!("{}", HexFmt(&row_1.to_bytes()));
            assert_eq!(row_1_hex, vector[2]);
        }

        Ok(())
    }
}
