use crate::read::{Bytes, Error, Result};

/// Iterator over the function starts in a `LC_FUNCTION_STARTS` load command.
#[derive(Debug, Default, Clone, Copy)]
pub struct FunctionStartsIterator<'data> {
    data: Bytes<'data>,
    addr: u64,
}

impl<'data> FunctionStartsIterator<'data> {
    pub(super) fn new(data: &'data [u8], addr: u64) -> Self {
        FunctionStartsIterator {
            data: Bytes(data),
            addr,
        }
    }
}

impl<'data> Iterator for FunctionStartsIterator<'data> {
    type Item = Result<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        let delta = match self.data.read_uleb128() {
            Ok(0) => return None,
            Ok(delta) => delta,
            Err(()) => {
                self.data = Bytes(&[]);
                return Some(Err(Error("Invalid ULEB128 in LC_FUNCTION_STARTS")));
            }
        };

        self.addr = match self.addr.checked_add(delta) {
            Some(addr) => addr,
            None => {
                self.data = Bytes(&[]);
                return Some(Err(Error("Address overflow in LC_FUNCTION_STARTS")));
            }
        };

        Some(Ok(self.addr))
    }
}
