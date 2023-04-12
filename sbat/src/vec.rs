// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Error, Result};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use core::fmt;

/// Trait for [`Vec`]-like containers.
///
/// This allows storage for metadata and revocations to be either
/// dynamically-allocated (like a [`Vec`]) or of a fixed size (like an
/// array).
///
/// `Veclike` is implemented for [`SliceVec`] and [`ArrayVec`]. If the
/// `alloc` feature is enabled it is also implemented for [`Vec`].
///
/// [`Vec`]: https://doc.rust-lang.org/stable/alloc/vec/struct.Vec.html
pub trait Veclike<T> {
    /// Try to add a new element to the end of the container. If the
    /// container is full this must return [`Error::TooManyRecords`].
    fn try_push(&mut self, t: T) -> Result<()>;

    /// Get the data as a slice.
    fn as_slice(&self) -> &[T];

    /// Set the container's length to zero.
    fn clear(&mut self);
}

/// Wrapper around a slice that allows it to act like a [`Vec`]. The
/// capacity is limited to the number of elements in the slice.
///
/// [`Vec`]: https://doc.rust-lang.org/stable/alloc/vec/struct.Vec.html
pub struct SliceVec<'a, T> {
    slice: &'a mut [T],
    len: usize,
}

impl<'a, T> SliceVec<'a, T> {
    /// Create a new `SliceVec`.
    pub fn new(slice: &'a mut [T]) -> Self {
        Self { slice, len: 0 }
    }
}

impl<'a, T: fmt::Debug> fmt::Debug for SliceVec<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SliceVec").field(&self.as_slice()).finish()
    }
}

impl<'a, T> Veclike<T> for SliceVec<'a, T> {
    fn try_push(&mut self, t: T) -> Result<()> {
        if self.len < self.slice.len() {
            self.slice[self.len] = t;
            self.len += 1;
            Ok(())
        } else {
            Err(Error::TooManyRecords)
        }
    }

    fn as_slice(&self) -> &[T] {
        &self.slice[..self.len]
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

impl<'a, T, const N: usize> Veclike<T> for ArrayVec<T, N> {
    fn try_push(&mut self, t: T) -> Result<()> {
        self.try_push(t).map_err(|_| Error::TooManyRecords)
    }

    fn as_slice(&self) -> &[T] {
        self.as_slice()
    }

    fn clear(&mut self) {
        self.clear()
    }
}

#[cfg(feature = "alloc")]
impl<T> Veclike<T> for Vec<T> {
    fn try_push(&mut self, t: T) -> Result<()> {
        self.push(t);
        Ok(())
    }

    fn as_slice(&self) -> &[T] {
        self.as_slice()
    }

    fn clear(&mut self) {
        self.clear()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_fixed_size(vec: &mut dyn Veclike<u8>) {
        assert!(vec.as_slice().is_empty());

        assert!(vec.try_push(1).is_ok());
        assert_eq!(vec.as_slice(), [1]);

        assert!(vec.try_push(2).is_ok());
        assert_eq!(vec.as_slice(), [1, 2]);

        assert!(vec.try_push(3).is_err());
        assert_eq!(vec.as_slice(), [1, 2]);

        vec.clear();
        assert!(vec.as_slice().is_empty());
    }

    #[test]
    fn array_vec() {
        let mut array = ArrayVec::<u8, 2>::new();
        check_fixed_size(&mut array);
    }

    #[test]
    fn slice_vec() {
        let mut array = [0u8; 2usize];
        let mut sv = SliceVec::new(&mut array);
        check_fixed_size(&mut sv);
    }

    #[cfg(feature = "alloc")]
    fn check_dynamic_size(vec: &mut dyn Veclike<u8>) {
        assert!(vec.as_slice().is_empty());

        assert!(vec.try_push(1).is_ok());
        assert_eq!(vec.as_slice(), [1]);

        assert!(vec.try_push(2).is_ok());
        assert_eq!(vec.as_slice(), [1, 2]);

        vec.clear();
        assert!(vec.as_slice().is_empty());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn vec_vec() {
        let mut v = Vec::new();
        check_dynamic_size(&mut v);
    }
}
