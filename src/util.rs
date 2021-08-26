// Hashing

use tiny_keccak::{Hasher, Sha3};

pub(crate) fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    sha3.update(data);
    let mut output = [0u8; 32];
    sha3.finalize(&mut output);
    output
}

// Byte conversions

use crate::error::{FromBytesError, FromBytesResult};
use group::{CurveAffine, CurveProjective, EncodedPoint};

use crate::{PK_SIZE, SK_SIZE};
use ff::{Field, PrimeField};
use pairing::bls12_381::{Fr, FrRepr, G1Affine, G1};

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

pub fn g1_from_be_bytes(bytes: [u8; PK_SIZE]) -> FromBytesResult<G1> {
    let mut compressed: <G1Affine as CurveAffine>::Compressed = EncodedPoint::empty();
    compressed.as_mut().copy_from_slice(&bytes);
    let opt_affine = compressed.into_affine().ok();
    let projective = opt_affine.ok_or(FromBytesError::Invalid)?.into_projective();
    Ok(projective)
}

pub fn g1_to_be_bytes(g1: G1) -> [u8; PK_SIZE] {
    let mut bytes = [0u8; PK_SIZE];
    bytes.copy_from_slice(g1.into_affine().into_compressed().as_ref());
    bytes
}

// derivation index conversions

pub(crate) fn derivation_index_into_fr(v: &[u8]) -> Fr {
    // use number of rounds as a salt to avoid
    // any child hash giving the same sequence
    index_and_rounds_into_fr(v, 0)
}

fn index_and_rounds_into_fr(v: &[u8], rounds: u8) -> Fr {
    let mut sha3 = Sha3::v256();
    sha3.update(v);
    sha3.update(&[rounds]);
    let mut h = [0u8; 32];
    sha3.finalize(&mut h);
    // If the hash bytes is larger than Fr::MAX, ie h > 0x73eda753... the
    // deserialization into Fr will throw an error. If that happens we need to
    // do repeated rounds of hashing until we find a hash less than Fr::MAX.
    match fr_from_be_bytes(h) {
        Ok(fr) => {
            // if fr is 0 or 1 do another round of hashing
            // x * 0 = 0 which is a constant
            // x * 1 = x which gives the same key
            // it's extremely unlikely to find hash(vr) == 0 or 1
            // so we could probably go without this check
            if fr == Fr::zero() || fr == Fr::one() {
                return index_and_rounds_into_fr(&h, rounds + 1);
            }
            fr
        }
        Err(_) => index_and_rounds_into_fr(&h, rounds + 1),
    }
}
