use object::build;
use std::{error, fmt, io};

/// An error that occurred while rewriting a file.
#[derive(Debug)]
pub struct Error {
    inner: ErrorInner,
}

#[derive(Debug)]
enum ErrorInner {
    Io(io::Error),
    Parse(build::Error),
    Write(build::Error),
    Modify(String),
}

/// The kind of error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// A parse error occurred while reading the file.
    Parse,
    /// A validation error occurred while writing the file.
    Write,
    /// An I/O error occurred while writing the file.
    Io(io::ErrorKind),
    /// A validation error occurred while modifying the file.
    Modify,
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            ErrorInner::Io(e) => e.fmt(f),
            ErrorInner::Parse(e) => e.fmt(f),
            ErrorInner::Write(e) => e.fmt(f),
            ErrorInner::Modify(e) => e.fmt(f),
        }
    }
}

impl error::Error for Error {}

impl Error {
    /// Get the kind of error.
    pub fn kind(&self) -> ErrorKind {
        match &self.inner {
            ErrorInner::Io(e) => ErrorKind::Io(e.kind()),
            ErrorInner::Parse(_) => ErrorKind::Parse,
            ErrorInner::Write(_) => ErrorKind::Write,
            ErrorInner::Modify(_) => ErrorKind::Modify,
        }
    }

    pub(crate) fn io(error: io::Error) -> Self {
        Self {
            inner: ErrorInner::Io(error),
        }
    }

    pub(crate) fn parse(error: build::Error) -> Self {
        Self {
            inner: ErrorInner::Parse(error),
        }
    }

    pub(crate) fn write(error: build::Error) -> Self {
        Self {
            inner: ErrorInner::Write(error),
        }
    }

    pub(crate) fn modify(message: impl Into<String>) -> Self {
        Self {
            inner: ErrorInner::Modify(message.into()),
        }
    }
}

/// The  `Result` type for this library.
pub type Result<T> = std::result::Result<T, Error>;
