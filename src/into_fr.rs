use crate::blst_ops::{fr_negate, hash_to_fr};
use blst::{blst_fr, blst_fr_from_scalar, blst_scalar, blst_scalar_from_bendian};

/// A conversion into an element of the field `Fr`.
pub trait IntoFr: Copy {
    /// Converts `self` to a field element.
    fn into_fr(self) -> blst_fr;
}

impl IntoFr for blst_fr {
    fn into_fr(self) -> blst_fr {
        self
    }
}

impl IntoFr for &[u8] {
    fn into_fr(self) -> blst_fr {
        hash_to_fr(self)
    }
}

impl IntoFr for u64 {
    fn into_fr(self) -> blst_fr {
        let mut fr = blst_fr::default();
        let mut scalar = blst_scalar::default();
        let mut bytes = [0u8; 32];
        // cannot use blst_fr_from_uint64 since it leaves junk in the most
        // significant 24 bytes
        let u64bytes = self.to_be_bytes();
        bytes[24..(8 + 24)].clone_from_slice(&u64bytes[..8]);
        unsafe {
            blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
            blst_fr_from_scalar(&mut fr, &scalar);
        }
        fr
    }
}

impl IntoFr for usize {
    fn into_fr(self) -> blst_fr {
        (self as u64).into_fr()
    }
}

impl IntoFr for i32 {
    fn into_fr(self) -> blst_fr {
        if self >= 0 {
            (self as u64).into_fr()
        } else {
            let mut result = ((-self) as u64).into_fr();
            fr_negate(&mut result);
            result
        }
    }
}

impl IntoFr for i64 {
    fn into_fr(self) -> blst_fr {
        if self >= 0 {
            (self as u64).into_fr()
        } else {
            let mut result = ((-self) as u64).into_fr();
            fr_negate(&mut result);
            result
        }
    }
}

impl<'a, T: IntoFr> IntoFr for &'a T {
    fn into_fr(self) -> blst_fr {
        (*self).into_fr()
    }
}
