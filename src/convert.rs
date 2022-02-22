//! Conversion between bls12_381 types and bytes.

use crate::error::{FromBytesError, FromBytesResult};
use group::{CurveAffine, CurveProjective, EncodedPoint};

use crate::{PK_SIZE, SIG_SIZE, SK_SIZE};
use ff::PrimeField;
use pairing::bls12_381::{Fr, FrRepr, G1Affine, G2Affine, G1, G2};

/// Convert big endian bytes to bls12_381::Fr
pub fn fr_from_be_bytes(bytes: [u8; SK_SIZE]) -> FromBytesResult<Fr> {
    let mut le_bytes = bytes;
    le_bytes.reverse();
    let mut fr_u64s = [0u64; 4];
    for i in 0..4 {
        let mut next_u64_bytes = [0u8; 8];
        for j in 0..8 {
            next_u64_bytes[j] = le_bytes[i * 8 + j];
        }
        fr_u64s[i] = u64::from_le_bytes(next_u64_bytes);
    }
    Ok(Fr::from_repr(FrRepr(fr_u64s))?)
}

/// Convert bls12_381::Fr to big endian bytes
pub fn fr_to_be_bytes(fr: Fr) -> [u8; SK_SIZE] {
    let mut bytes = [0u8; SK_SIZE];
    // iterating 4 u64s which are in order suiting little endian bytes
    // and must be reversed to get big endian bytes
    fr.into_repr().0.iter().enumerate().for_each(|(le_i, n)| {
        let be_i = 4 - le_i - 1;
        n.to_be_bytes().iter().enumerate().for_each(|(j, byte)| {
            bytes[8 * be_i + j] = *byte;
        });
    });
    bytes
}

/// Convert big endian bytes to bls12_381::G1
pub fn g1_from_be_bytes(bytes: [u8; PK_SIZE]) -> FromBytesResult<G1> {
    let mut compressed: <G1Affine as CurveAffine>::Compressed = EncodedPoint::empty();
    compressed.as_mut().copy_from_slice(&bytes);
    let opt_affine = compressed.into_affine().ok();
    let projective = opt_affine.ok_or(FromBytesError::Invalid)?.into_projective();
    Ok(projective)
}

/// Convert bls12_381::G1 to big endian bytes
pub fn g1_to_be_bytes(g1: G1) -> [u8; PK_SIZE] {
    let mut bytes = [0u8; PK_SIZE];
    bytes.copy_from_slice(g1.into_affine().into_compressed().as_ref());
    bytes
}

/// Convert big endian bytes to bls12_381::G2
pub fn g2_from_be_bytes(bytes: [u8; SIG_SIZE]) -> FromBytesResult<G2> {
    let mut compressed: <G2Affine as CurveAffine>::Compressed = EncodedPoint::empty();
    compressed.as_mut().copy_from_slice(&bytes);
    let opt_affine = compressed.into_affine().ok();
    let projective = opt_affine.ok_or(FromBytesError::Invalid)?.into_projective();
    Ok(projective)
}

/// Convert bls12_381::G2 to big endian bytes
pub fn g2_to_be_bytes(g2: G2) -> [u8; SIG_SIZE] {
    let mut bytes = [0u8; SIG_SIZE];
    bytes.copy_from_slice(g2.into_affine().into_compressed().as_ref());
    bytes
}
