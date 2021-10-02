//! Conversion between bls12_381 types and bytes.

use crate::{PK_SIZE, SIG_SIZE, SK_SIZE};
use crate::error::{Error, Result};

use blst::{
    blst_bendian_from_scalar, blst_expand_message_xmd, blst_final_exp, blst_fp, blst_fp12,
    blst_fp12_is_one, blst_fp12_mul, blst_fp6, blst_fr, blst_fr_add, blst_fr_cneg,
    blst_fr_from_scalar, blst_fr_inverse, blst_fr_mul, blst_fr_sub, blst_miller_loop_lines,
    blst_p1, blst_p1_add, blst_p1_affine, blst_p1_affine_compress, blst_p1_cneg,
    blst_p1_deserialize, blst_p1_from_affine, blst_p1_mult, blst_p1_to_affine, blst_p2,
    blst_p2_add, blst_p2_affine, blst_p2_affine_compress, blst_p2_deserialize, blst_p2_from_affine,
    blst_p2_to_affine, blst_precompute_lines, blst_scalar, blst_scalar_from_be_bytes,
    blst_scalar_from_bendian, blst_scalar_from_fr, blst_sign_pk_in_g1, blst_sign_pk_in_g2,
    BLST_ERROR,
};

const FR_MAX_BYTES: [u8; 32] = [
    115, 237, 167, 83, 41, 157, 125, 72, 51, 57, 216, 8, 9, 161, 216, 5, 83, 189, 164, 2, 255, 254,
    91, 254, 255, 255, 255, 255, 0, 0, 0, 1,
];

const DST: &[u8; 43] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

// Hash to scalar L parameter
// See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html#section-5.1-2
// L = ceil((ceil(log2(p)) + k) / 8)
// where for bls p is the scalar ie 255 bits
// and k is 128 bits security target
const HTS_L: usize = 48;

// Hash to scalar Uniform Bytes size
// See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html#section-5.4.1-5
// This is 64 bytes because uniform bytes comes in groups of 32 bytes (for
// sha256), which is then truncated down to L bytes, ie 48.
// One group of 32 bytes would not be enough, two groups ie 64 bytes is enough
// to extract the required 48 bytes.
const HTS_UB_SIZE: usize = 64;

pub(crate) const FR_ONE: blst_fr = blst_fr {
    l: [
        8589934590,
        6378425256633387010,
        11064306276430008309,
        1739710354780652911,
    ],
};

pub(crate) const FR_ZERO: blst_fr = blst_fr { l: [0, 0, 0, 0] };

pub(crate) const P1_ZERO: blst_p1 = blst_p1 {
    x: blst_fp {
        l: [0, 0, 0, 0, 0, 0],
    },
    y: blst_fp {
        l: [0, 0, 0, 0, 0, 0],
    },
    z: blst_fp {
        l: [0, 0, 0, 0, 0, 0],
    },
};

pub(crate) const P1_ONE: blst_p1 = blst_p1 {
    x: blst_fp {
        l: [
            6679831729115696150,
            8653662730902241269,
            1535610680227111361,
            17342916647841752903,
            17135755455211762752,
            1297449291367578485,
        ],
    },
    y: blst_fp {
        l: [
            13451288730302620273,
            10097742279870053774,
            15949884091978425806,
            5885175747529691540,
            1016841820992199104,
            845620083434234474,
        ],
    },
    z: blst_fp {
        l: [
            8505329371266088957,
            17002214543764226050,
            6865905132761471162,
            8632934651105793861,
            6631298214892334189,
            1582556514881692819,
        ],
    },
};

/// Convert big endian bytes to bls12_381::Fr
pub fn fr_from_be_bytes(bytes: [u8; SK_SIZE]) -> Result<blst_fr> {
    if bytes > FR_MAX_BYTES {
        return Err(Error::InvalidBytes);
    }
    let mut scalar = blst_scalar::default();
    let mut fr = blst_fr::default();
    unsafe {
        blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
        blst_fr_from_scalar(&mut fr, &scalar);
    }
    Ok(fr)
}

/// Convert bls12_381::Fr to big endian bytes
pub(crate) fn fr_to_be_bytes(fr: blst_fr) -> [u8; SK_SIZE] {
    let mut scalar = blst_scalar::default();
    let mut bytes = [0u8; SK_SIZE];
    unsafe {
        blst_scalar_from_fr(&mut scalar, &fr);
        blst_bendian_from_scalar(bytes.as_mut_ptr(), &scalar);
    }
    bytes
}

/// Convert big endian bytes to blst_p1
pub fn p1_from_be_bytes(bytes: [u8; PK_SIZE]) -> Result<blst_p1> {
    if (bytes[0] & 0x80) != 0 {
        let mut p1_affine = blst_p1_affine::default();
        let err = unsafe { blst_p1_deserialize(&mut p1_affine, bytes.as_ptr()) };
        if err != BLST_ERROR::BLST_SUCCESS {
            return Err(Error::InvalidBytes);
        }
        let mut p1 = blst_p1::default();
        unsafe { blst_p1_from_affine(&mut p1, &p1_affine) };
        Ok(p1)
    } else {
        Err(Error::InvalidBytes)
    }
}

/// Convert blst_p1_affine to big endian bytes
pub(crate) fn p1_to_be_bytes(p1: &blst_p1) -> [u8; PK_SIZE] {
    let mut p1_affine = blst_p1_affine::default();
    let mut bytes = [0u8; PK_SIZE];
    unsafe {
        blst_p1_to_affine(&mut p1_affine, p1);
        blst_p1_affine_compress(bytes.as_mut_ptr(), &p1_affine);
    }
    bytes
}

/// Convert big endian bytes to blst_p2
pub fn p2_from_be_bytes(bytes: [u8; SIG_SIZE]) -> Result<blst_p2> {
    if (bytes[0] & 0x80) != 0 {
        let mut p2_affine = blst_p2_affine::default();
        let err = unsafe { blst_p2_deserialize(&mut p2_affine, bytes.as_ptr()) };
        if err != BLST_ERROR::BLST_SUCCESS {
            return Err(Error::InvalidBytes);
        }
        let mut p2 = blst_p2::default();
        unsafe {
            blst_p2_from_affine(&mut p2, &p2_affine);
        }
        Ok(p2)
    } else {
        Err(Error::InvalidBytes)
    }
}

/// Convert blst_p2 to big endian bytes
pub(crate) fn p2_to_be_bytes(p2: &blst_p2) -> [u8; SIG_SIZE] {
    let mut bytes = [0; SIG_SIZE];
    let mut p2_affine = blst_p2_affine::default();
    unsafe {
        blst_p2_to_affine(&mut p2_affine, p2);
        blst_p2_affine_compress(bytes.as_mut_ptr(), &p2_affine);
    }
    bytes
}

pub(crate) fn p1_p2_to_fp12(p: &blst_p1, q: &blst_p2) -> blst_fp12 {
    // TODO IC check p and q are valid? Or is it already done in miller loop?
    let mut p_affine = blst_p1_affine::default();
    let mut q_affine = blst_p2_affine::default();
    let mut pair = blst_fp12::default();
    let mut lines = [blst_fp6::default(); 68];
    unsafe {
        blst_p1_to_affine(&mut p_affine, p);
        blst_p2_to_affine(&mut q_affine, q);
        blst_precompute_lines(lines.as_mut_ptr(), &q_affine);
        blst_miller_loop_lines(&mut pair, lines.as_ptr(), &p_affine);
    }
    pair
}

fn p1_mul_neg_one(p1: &mut blst_p1) {
    unsafe {
        blst_p1_cneg(p1, true);
    }
}

pub(crate) fn p1_mul_assign_scalar(p1: &mut blst_p1, scalar: &blst_scalar) {
    let size = scalar_num_bits(scalar);
    unsafe {
        blst_p1_mult(p1, p1, scalar.b.as_ptr(), size);
    }
}

fn scalar_num_bits(scalar: &blst_scalar) -> usize {
    let mut size = 256;
    for i in 0..scalar.b.len() {
        if scalar.b[31 - i] > 0 {
            size -= scalar.b[31 - i].leading_zeros() as usize;
            break;
        } else {
            size -= 8;
        }
    }
    size
}

pub(crate) fn p1_mul_fr(p1: &blst_p1, fr: &blst_fr) -> blst_p1 {
    let mut scalar = blst_scalar::default();
    let mut out = blst_p1::default();
    unsafe {
        // can't use blst_p1_mult here
        blst_scalar_from_fr(&mut scalar, fr);
        blst_sign_pk_in_g2(&mut out, p1, &scalar);
    }
    out
}

pub(crate) fn p2_mul_fr(p2: &blst_p2, fr: &blst_fr) -> blst_p2 {
    let mut out = blst_p2::default();
    let mut scalar = blst_scalar::default();
    unsafe {
        // TODO consider using blst_p2_mult here
        blst_scalar_from_fr(&mut scalar, fr);
        blst_sign_pk_in_g1(&mut out, p2, &scalar);
    }
    out
}

pub(crate) fn p2_add_assign(a: &mut blst_p2, b: &blst_p2) {
    unsafe {
        blst_p2_add(a, a, b);
    }
}

pub(crate) fn p1_add_assign(a: &mut blst_p1, b: &blst_p1) {
    unsafe {
        blst_p1_add(a, a, b);
    }
}

pub(crate) fn equal_pairs(ap: &blst_p1, aq: &blst_p2, bp: &blst_p1, bq: &blst_p2) -> bool {
    let mut neg_bp = *bp;
    p1_mul_neg_one(&mut neg_bp);
    let pair_a = p1_p2_to_fp12(ap, aq);
    let pair_b = p1_p2_to_fp12(&neg_bp, bq);
    let mut gt = blst_fp12::default();
    let mut gt_final = blst_fp12::default();
    unsafe {
        blst_fp12_mul(&mut gt, &pair_a, &pair_b);
        blst_final_exp(&mut gt_final, &gt);
        blst_fp12_is_one(&gt_final)
    }
}

pub(crate) fn fr_add_assign(a: &mut blst_fr, b: &blst_fr) {
    unsafe {
        blst_fr_add(a, a, b);
    }
}

pub(crate) fn fr_sub_fr(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    unsafe {
        blst_fr_sub(&mut out, a, b);
    }
    out
}

pub(crate) fn fr_sub_assign(a: &mut blst_fr, b: &blst_fr) {
    unsafe {
        blst_fr_sub(a, a, b);
    }
}

pub(crate) fn fr_mul_fr(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    unsafe {
        blst_fr_mul(&mut out, a, b);
    }
    out
}

pub(crate) fn fr_mul_assign(a: &mut blst_fr, b: &blst_fr) {
    unsafe {
        blst_fr_mul(a, a, b);
    }
}

pub(crate) fn fr_to_scalar(a: &blst_fr) -> blst_scalar {
    let mut out = blst_scalar::default();
    unsafe {
        blst_scalar_from_fr(&mut out, a);
    }
    out
}

pub(crate) fn fr_negate(a: &mut blst_fr) {
    unsafe {
        blst_fr_cneg(a, a, true);
    }
}

pub(crate) fn fr_inverse(a: &mut blst_fr) {
    unsafe {
        blst_fr_inverse(a, a);
    }
}

pub(crate) fn hash_to_fr(a: &[u8]) -> blst_fr {
    // Hash to scalar then convert to fr.
    // See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html#section-5-4
    let mut expanded = [0u8; HTS_UB_SIZE];
    let mut scalar = blst_scalar::default();
    let mut fr = blst_fr::default();
    unsafe {
        blst_expand_message_xmd(
            expanded.as_mut_ptr(),
            HTS_L,
            a.as_ptr(),
            a.len(),
            DST.as_ptr(),
            DST.len(),
        );
        blst_scalar_from_be_bytes(&mut scalar, expanded[0..HTS_L].as_ptr(), HTS_L);
        blst_fr_from_scalar(&mut fr, &scalar);
    }
    fr
}
