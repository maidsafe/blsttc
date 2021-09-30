//! Crypto errors.
use blst::BLST_ERROR as BlstError;
use thiserror::Error;

/// A crypto result.
pub type Result<T> = ::std::result::Result<T, Error>;

/// A crypto error.
#[derive(Clone, Eq, PartialEq, Debug, Error)]
pub enum Error {
    /// Not enough signature shares.
    #[error("Not enough signature shares")]
    NotEnoughShares,
    /// Signature shares contain a duplicated index.
    #[error("Signature shares contain a duplicated index")]
    DuplicateEntry,
    /// The degree is too high for the coefficients to be indexed by `usize`.
    #[error("The degree is too high for the coefficients to be indexed by usize.")]
    DegreeTooHigh,
    /// An error reading a structure from an array of bytes. Invalid bytes representation.
    #[error("Invalid bytes representation.")]
    InvalidBytes,
    /// BLST error
    #[error("BLST error: {0}")]
    BlstError(String),
}

impl From<BlstError> for Error {
    fn from(error: BlstError) -> Self {
        if error == BlstError::BLST_SUCCESS {
            Error::BlstError(format!(
                "received inconsistent and unexpected result: {:?}",
                error
            ))
        } else {
            Error::BlstError(format!("{:?}", error))
        }
    }
}

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
