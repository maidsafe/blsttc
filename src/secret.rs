//! Utilities for working with secret values. This module includes functionality for overwriting
//! memory with zeros.

use crate::Fr;
use group::ff::Field;

/// Overwrites a single field element with zeros.
pub(crate) fn clear_fr(fr: &mut Fr) {
    *fr = Fr::zero();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::thread_rng;

    #[test]
    fn test_clear() {
        let mut rng = thread_rng();

        let mut fr: Fr = Fr::random(&mut rng);
        assert_ne!(fr, Fr::zero());

        clear_fr(&mut fr);
        assert_eq!(fr, Fr::zero());
    }
}
