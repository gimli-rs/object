use alloc::string::{String, ToString};
use core::{fmt, result};
#[cfg(feature = "std")]
use std::error;

use crate::{read, write};

/// The error type used within the build module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(#[cfg(feature = "keep-error-msg")] pub(crate) String);

impl Error {
    #[inline(always)]
    pub(super) fn new(#[allow(unused_variables)] message: impl Into<String>) -> Self {
        Self(
            #[cfg(feature = "keep-error-msg")]
            message.into(),
        )
    }
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str({
            #[cfg(feature = "keep-error-msg")]
            {
                &self.0
            }
            #[cfg(not(feature = "keep-error-msg"))]
            {
                "Error"
            }
        })
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {}

impl From<read::Error> for Error {
    fn from(error: read::Error) -> Error {
        Error(
            #[cfg(feature = "keep-error-msg")]
            error.0.to_string(),
        )
    }
}

impl From<write::Error> for Error {
    fn from(error: write::Error) -> Error {
        Error(
            #[cfg(feature = "keep-error-msg")]
            error.0,
        )
    }
}

/// The result type used within the build module.
pub type Result<T> = result::Result<T, Error>;
