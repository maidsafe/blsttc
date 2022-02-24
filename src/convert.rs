//! Conversion between bls12_381 types and bytes.

use blst::blst_scalar;

use crate::{
    error::{Error, Result},
    Fr, DST, G1, G2, PK_SIZE, SIG_SIZE, SK_SIZE,
};

pub(crate) fn derivation_index_into_fr(index: &[u8]) -> Fr {
    hash_to_field(index).unwrap_or_else(|_| {
        // If the new fr is zero (which should in practice never happen!) do a
        // second round of hash to field using zero as the input.
        // It feels like if this ever happens we should log this index value
        // since knowing a value that hashes to zero would be extremely handy
        // for tests.
        derivation_index_into_fr(&[0u8; 32])
    })
}

/// Generates a scalar as described in IETF hash to curve
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html#name-hashing-to-a-finite-field-2
/// There are two main candidates for converting arbitrary bytes to scalar:
/// * hash to field as described in hash to curve
/// * bls signature keygen based on hkdf
/// BLS Signature spec has strong recommendations about IKM which don't apply when deriving indexes.
/// Hash to field is also slightly faster than HKDF.
fn hash_to_field<T: AsRef<[u8]>>(msg: T) -> Result<Fr> {
    // hash_to may return None if the result is Fr::zero
    let scalar = blst_scalar::hash_to(msg.as_ref(), DST).ok_or(Error::HashToFieldIsZero)?;
    // converting blst::blst_scalar to blstrs::Scalar may return an error if
    // the value is not in the field.
    let fr = scalar.try_into();
    fr.map_err(|_| Error::HashToFieldIsZero)
}

pub(crate) fn fr_from_bytes(bytes: [u8; SK_SIZE]) -> Result<Fr> {
    // TODO IC remove unwrap here? I'm not sure if it's possible with CtOption
    let fr = Fr::from_bytes_be(&bytes);
    if fr.is_none().into() {
        return Err(Error::InvalidBytes);
    };
    Ok(fr.unwrap())
}

pub(crate) fn g1_from_bytes(bytes: [u8; PK_SIZE]) -> Result<G1> {
    // TODO IC remove unwrap here? I'm not sure if it's possible with CtOption
    let g1 = G1::from_compressed(&bytes);
    if g1.is_none().into() {
        return Err(Error::InvalidBytes);
    };
    Ok(g1.unwrap())
}

pub(crate) fn g2_from_bytes(bytes: [u8; SIG_SIZE]) -> Result<G2> {
    // TODO IC remove unwrap here? I'm not sure if it's possible with CtOption
    let g2 = G2::from_compressed(&bytes);
    if g2.is_none().into() {
        return Err(Error::InvalidBytes);
    };
    Ok(g2.unwrap())
}
