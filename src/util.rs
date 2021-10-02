//! Useful functions that operate on lower-level blst types.

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
