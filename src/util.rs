use crate::convert::fr_from_be_bytes;
use ff::Field;
use pairing::bls12_381::Fr;
use tiny_keccak::{Hasher, Sha3, Shake, Xof};

pub(crate) fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    sha3.update(data);
    let mut output = [0u8; 32];
    sha3.finalize(&mut output);
    output
}

pub(crate) fn derivation_index_into_fr(v: &[u8]) -> Fr {
    let mut shake = Shake::v256();
    shake.update(v);

    // Find the first valid 32 byte window into the SHAKE XOF stream that parses to a valid fr
    let mut fr_bytes = [0u8; 32];
    shake.squeeze(&mut fr_bytes);
    loop {
        match fr_from_be_bytes(fr_bytes) {
            // reject if fr is 0 or 1
            // x * 0 = 0 which is a constant
            // x * 1 = x which gives the same key
            // it's extremely unlikely to find hash(vr) == 0 or 1
            // so we could probably go without this check
            Ok(fr) if fr != Fr::zero() && fr != Fr::one() => return fr,
            _ => (),
        }

        // shift our fr_bytes window and try again
        fr_bytes.rotate_left(1);
        shake.squeeze(&mut fr_bytes[31..]);
    }
}
