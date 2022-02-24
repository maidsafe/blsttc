use std::cmp::Ordering;

use group::{prime::PrimeCurve, GroupEncoding};

/// Compares two curve elements and returns their `Ordering`.
pub fn cmp_projective<G: PrimeCurve>(x: &G, y: &G) -> Ordering {
    let xc = x.to_affine().to_bytes();
    let yc = y.to_affine().to_bytes();
    xc.as_ref().cmp(yc.as_ref())
}
