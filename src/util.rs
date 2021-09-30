use blst::blst_fr;
use crate::blst_ops::{
    fr_from_be_bytes,
    FR_ONE,
    FR_ZERO,
};
use tiny_keccak::{Hasher, Sha3};

pub(crate) fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    sha3.update(data);
    let mut output = [0u8; 32];
    sha3.finalize(&mut output);
    output
}

pub(crate) fn derivation_index_into_fr(v: &[u8]) -> blst_fr {
    // use number of rounds as a salt to avoid
    // any child hash giving the same sequence
    index_and_rounds_into_fr(v, 0)
}

fn index_and_rounds_into_fr(v: &[u8], rounds: u8) -> blst_fr {
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
            if fr == FR_ZERO || fr == FR_ONE {
                return index_and_rounds_into_fr(&h, rounds + 1);
            }
            fr
        }
        Err(_) => index_and_rounds_into_fr(&h, rounds + 1),
    }
}
