use std::cmp::Ordering;

use group::prime::PrimeCurveAffine;

/// Compares two curve elements and returns their `Ordering`.
pub fn cmp_affine<G: PrimeCurveAffine>(x: &G, y: &G) -> Ordering {
    let xc = x.to_bytes();
    let yc = y.to_bytes();
    xc.as_ref().cmp(yc.as_ref())
}
