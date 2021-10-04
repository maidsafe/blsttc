//! Useful functions that operate on lower-level blst types.

use crate::blst_ops::{fr_to_be_bytes, FR_ONE, FR_ZERO};
use crate::into_fr::IntoFr;
use crate::SK_SIZE;
use blst::{blst_fr, blst_fr_from_scalar, blst_keygen, blst_scalar};
use rand::RngCore;
use tiny_keccak::{Hasher, Sha3};

/// Generate a random fr using bls-sig-keygen as described in
/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-02#section-2.3
pub fn fr_random(mut rng: impl RngCore) -> blst_fr {
    let mut fr = blst_fr::default();
    let mut scalar = blst_scalar::default();
    let mut bytes = [0u8; SK_SIZE];
    let key_info = vec![];
    rng.fill_bytes(&mut bytes);
    unsafe {
        blst_keygen(&mut scalar, bytes.as_ptr(), SK_SIZE, key_info.as_ptr(), 0);
        blst_fr_from_scalar(&mut fr, &scalar);
    }
    fr
}

pub(crate) fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    sha3.update(data);
    let mut output = [0u8; 32];
    sha3.finalize(&mut output);
    output
}

pub(crate) fn derivation_index_into_fr<T: IntoFr>(index: T) -> blst_fr {
    let index_fr = index.into_fr();
    // Don't allow FR_ZERO or FR_ONE as a derivation index since
    // parent * 0 = 0
    // parent * 1 = parent
    if index_fr == FR_ZERO || index_fr == FR_ONE {
        let fr_bytes = fr_to_be_bytes(index_fr);
        return derivation_index_into_fr(&fr_bytes[..]);
    }
    index_fr
}
