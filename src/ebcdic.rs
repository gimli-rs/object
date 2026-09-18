#[cfg(any(feature = "read_core", feature = "write_core"))]
use alloc::string::String;
#[cfg(any(feature = "read_core", feature = "write_core"))]
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt::{self, Write};
use core::ops::Deref;

/// Mapping from IBM-1047 to ISO-8859-1.
///
/// IBM-1047 is a permutation of ISO-8859-1, so each character maps to a distinct code point.
///
/// Variation: 0x15 (NL) maps to U+000A and 0x25 (LF) maps to U+0085, following z/OS conventions.
#[rustfmt::skip]
static IBM1047_TO_ISO88591: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x9c, 0x09, 0x86, 0x7f, 0x97, 0x8d, 0x8e, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x9d, 0x0a, 0x08, 0x87, 0x18, 0x19, 0x92, 0x8f, 0x1c, 0x1d, 0x1e, 0x1f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x17, 0x1b, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x05, 0x06, 0x07,
    0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, 0x98, 0x99, 0x9a, 0x9b, 0x14, 0x15, 0x9e, 0x1a,
    0x20, 0xa0, 0xe2, 0xe4, 0xe0, 0xe1, 0xe3, 0xe5, 0xe7, 0xf1, 0xa2, 0x2e, 0x3c, 0x28, 0x2b, 0x7c,
    0x26, 0xe9, 0xea, 0xeb, 0xe8, 0xed, 0xee, 0xef, 0xec, 0xdf, 0x21, 0x24, 0x2a, 0x29, 0x3b, 0x5e,
    0x2d, 0x2f, 0xc2, 0xc4, 0xc0, 0xc1, 0xc3, 0xc5, 0xc7, 0xd1, 0xa6, 0x2c, 0x25, 0x5f, 0x3e, 0x3f,
    0xf8, 0xc9, 0xca, 0xcb, 0xc8, 0xcd, 0xce, 0xcf, 0xcc, 0x60, 0x3a, 0x23, 0x40, 0x27, 0x3d, 0x22,
    0xd8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0xab, 0xbb, 0xf0, 0xfd, 0xfe, 0xb1,
    0xb0, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xaa, 0xba, 0xe6, 0xb8, 0xc6, 0xa4,
    0xb5, 0x7e, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0xa1, 0xbf, 0xd0, 0x5b, 0xde, 0xae,
    0xac, 0xa3, 0xa5, 0xb7, 0xa9, 0xa7, 0xb6, 0xbc, 0xbd, 0xbe, 0xdd, 0xa8, 0xaf, 0x5d, 0xb4, 0xd7,
    0x7b, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0xad, 0xf4, 0xf6, 0xf2, 0xf3, 0xf5,
    0x7d, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0xb9, 0xfb, 0xfc, 0xf9, 0xfa, 0xff,
    0x5c, 0xf7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0xb2, 0xd4, 0xd6, 0xd2, 0xd3, 0xd5,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xb3, 0xdb, 0xdc, 0xd9, 0xda, 0x9f,
];

/// Mapping from ISO-8859-1 to IBM-1047.
static ISO88591_TO_IBM1047: [u8; 256] = {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        table[IBM1047_TO_ISO88591[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// A borrowed view of IBM-1047 EBCDIC-encoded bytes.
#[repr(transparent)]
pub struct EbcdicStr([u8]);

impl EbcdicStr {
    pub fn from_bytes(bytes: &[u8]) -> &EbcdicStr {
        // Safe because of #[repr(transparent)] over [u8].
        unsafe { &*(bytes as *const [u8] as *const EbcdicStr) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn chars(&self) -> impl Iterator<Item = char> + '_ {
        self.0
            .iter()
            // char::from maps ISO-8859-1 to Unicode.
            .map(|b| char::from(IBM1047_TO_ISO88591[usize::from(*b)]))
    }

    #[cfg(any(feature = "read_core", feature = "write_core"))]
    pub fn to_utf8(&self) -> String {
        self.chars().collect()
    }
}

impl fmt::Debug for EbcdicStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EbcdicStr(\"")?;
        for c in self.chars() {
            // Match the `Debug` output of the equivalent `str`.
            if c == '\'' {
                f.write_char(c)?;
            } else {
                write!(f, "{}", c.escape_debug())?;
            }
        }
        f.write_str("\")")
    }
}

impl fmt::Display for EbcdicStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.chars() {
            f.write_char(c)?;
        }
        Ok(())
    }
}

impl PartialEq for EbcdicStr {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for EbcdicStr {}

/// An owned, growable buffer of IBM-1047 EBCDIC-encoded bytes.
#[cfg(any(feature = "read_core", feature = "write_core"))]
#[derive(Clone, Default)]
pub struct EbcdicString(Vec<u8>);

#[cfg(any(feature = "read_core", feature = "write_core"))]
impl EbcdicString {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        EbcdicString(bytes)
    }

    #[cfg(test)]
    pub fn from_utf8(s: &str) -> Option<Self> {
        let out: Option<Vec<u8>> = s
            .chars()
            // u8::try_from maps Unicode to ISO-8859-1.
            .map(|c| Some(ISO88591_TO_IBM1047[usize::from(u8::try_from(c).ok()?)]))
            .collect();
        out.map(EbcdicString)
    }
}

#[cfg(any(feature = "read_core", feature = "write_core"))]
impl Deref for EbcdicString {
    type Target = EbcdicStr;
    fn deref(&self) -> &EbcdicStr {
        EbcdicStr::from_bytes(&self.0)
    }
}

#[cfg(any(feature = "read_core", feature = "write_core"))]
impl Borrow<EbcdicStr> for EbcdicString {
    fn borrow(&self) -> &EbcdicStr {
        self
    }
}

#[cfg(any(feature = "read_core", feature = "write_core"))]
impl AsRef<[u8]> for EbcdicString {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(any(feature = "read_core", feature = "write_core"))]
impl fmt::Debug for EbcdicString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
#[cfg(any(feature = "read_core", feature = "write_core"))]
impl fmt::Display for EbcdicString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

/// A fixed-width buffer of `N` IBM-1047 EBCDIC-encoded bytes.
#[derive(Clone, Copy)]
pub struct EbcdicArray<const N: usize>([u8; N]);

impl<const N: usize> EbcdicArray<N> {
    #[cfg(test)]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        EbcdicArray(bytes)
    }

    pub const fn into_inner(self) -> [u8; N] {
        self.0
    }

    /// Encodes an ASCII string literal at compile time.
    ///
    /// Panics if bytes contains non-ASCII.
    pub const fn from_ascii(bytes: [u8; N]) -> Self {
        let mut out = [0; N];
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b >= 0x80 {
                panic!("EbcdicArray::from_ascii: input must be ASCII (bytes < 0x80)");
            }
            out[i] = ISO88591_TO_IBM1047[b as usize];
            i += 1;
        }
        EbcdicArray(out)
    }
}

impl<const N: usize> Deref for EbcdicArray<N> {
    type Target = EbcdicStr;
    fn deref(&self) -> &EbcdicStr {
        EbcdicStr::from_bytes(&self.0)
    }
}

impl<const N: usize> Borrow<EbcdicStr> for EbcdicArray<N> {
    fn borrow(&self) -> &EbcdicStr {
        self
    }
}

impl<const N: usize> fmt::Debug for EbcdicArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
impl<const N: usize> fmt::Display for EbcdicArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl<const N: usize> PartialEq for EbcdicArray<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<const N: usize> Eq for EbcdicArray<N> {}

#[cfg(test)]
#[cfg(any(feature = "read_core", feature = "write_core"))]
mod test {
    use super::{EbcdicArray, EbcdicString};
    use alloc::format;

    #[test]
    fn round_trip() {
        for b in 0..=255 {
            let a = EbcdicArray::from_bytes([b]);
            let u = a.to_utf8();
            let s = EbcdicString::from_utf8(&u).unwrap();
            assert_eq!(*a, *s);
        }
    }

    #[test]
    fn fmt() {
        for b in 0..=255 {
            let a = EbcdicArray::from_bytes([b]);
            let u = a.to_utf8();
            assert_eq!(format!("{}", a), u);
            assert_eq!(format!("{:?}", a), format!("EbcdicStr({:?})", u));
        }
    }
}
