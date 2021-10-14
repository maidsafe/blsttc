//! Utilities for working with secret values. This module includes functionality for overwriting
//! memory with zeros.

use crate::blst_ops::FR_ZERO;
use crate::Fr;

/// Overwrites a single field element with zeros.
pub(crate) fn clear_fr(fr: &mut Fr) {
    *fr = FR_ZERO
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blst_ops::FR_ZERO;
    use crate::util::fr_random;
    use rand::thread_rng;

    #[test]
    fn test_clear() {
        let mut rng = thread_rng();

        let mut fr = fr_random(&mut rng);
        assert_ne!(fr, FR_ZERO);

        clear_fr(&mut fr);
        assert_eq!(fr, FR_ZERO);
    }
}
