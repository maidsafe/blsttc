//! Crypto errors.
use thiserror::Error;

/// A crypto error.
#[derive(Clone, PartialEq, Debug, Error)]
pub enum Error {
    /// Not enough signature shares.
    #[error("Not enough shares for interpolation")]
    NotEnoughShares,
    /// Samples for interpolation contain a duplicated index.
    #[error("Samples for interpolation contain a duplicated index")]
    DuplicateEntry,
    /// The degree is too high for the coefficients to be indexed by `usize`.
    #[error("The degree is too high for the coefficients to be indexed by usize.")]
    DegreeTooHigh,
    /// An error reading a structure from an array of bytes. Invalid bytes representation.
    #[error("Invalid bytes representation.")]
    InvalidBytes,
    /// The result of Hash To Field is zero which should never happen.
    #[error("Hash To Field returned zero")]
    HashToFieldIsZero,
    /// An error converting to or from a hex representation of a key.
    #[error("Failed to convert the key from hex")]
    HexConversionFailed(#[from] hex::FromHexError),
}

/// A crypto result.
pub type Result<T> = ::std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;

    /// No-op function that compiles only if its argument is `Send + Sync`.
    fn is_send_and_sync<T: Send + Sync>(_: T) {}

    #[test]
    fn errors_are_send_and_sync() {
        is_send_and_sync(Error::NotEnoughShares);
    }
}
