// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Component, Entry, ImageSbat, PushError, RevocationSbat};
use arrayvec::ArrayVec;
use ascii::AsciiStr;
use core::fmt::{self, Display, Formatter};

/// Image SBAT metadata.
///
/// This contains SBAT entries parsed from the `.sbat` section of a UEFI
/// PE executable.
///
/// See the [crate] documentation for a usage example.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageSbatArray<'a, const N: usize>(ArrayVec<Entry<'a>, N>);

impl<'a, const N: usize> ImageSbatArray<'a, N> {
    /// Create an empty `ImageSbatArray`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<'a, const N: usize> ImageSbat<'a> for ImageSbatArray<'a, N> {
    fn entries(&self) -> &[Entry<'a>] {
        &self.0
    }

    fn try_push(&mut self, entry: Entry<'a>) -> Result<(), PushError> {
        self.0.try_push(entry).map_err(|_| PushError)
    }
}

impl<'a, const N: usize> Display for ImageSbatArray<'a, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.to_csv(f)
    }
}

/// SBAT revocation data.
///
/// This contains SBAT revocation data parsed from a UEFI variable such
/// as `SbatLevel`.
///
/// See the [crate] documentation for a usage example.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevocationSbatArray<'a, const N: usize> {
    date: Option<&'a AsciiStr>,
    components: ArrayVec<Component<'a>, N>,
}

impl<'a, const N: usize> RevocationSbatArray<'a, N> {
    /// Create an empty `RevocationSbatArray`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<'a, const N: usize> RevocationSbat<'a> for RevocationSbatArray<'a, N> {
    fn date(&self) -> Option<&AsciiStr> {
        self.date
    }

    fn set_date(&mut self, date: Option<&'a AsciiStr>) {
        self.date = date;
    }

    fn revoked_components(&self) -> &[Component<'a>] {
        &self.components
    }

    fn try_push(&mut self, component: Component<'a>) -> Result<(), PushError> {
        self.components.try_push(component).map_err(|_| PushError)
    }
}

impl<'a, const N: usize> Display for RevocationSbatArray<'a, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.to_csv(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_push() {
        let mut image_sbat = ImageSbatArray::<1>::new();
        image_sbat.try_push(Entry::default()).unwrap();
        assert_eq!(image_sbat.try_push(Entry::default()), Err(PushError));

        let mut revocations = RevocationSbatArray::<1>::new();
        revocations.try_push(Component::default()).unwrap();
        assert_eq!(revocations.try_push(Component::default()), Err(PushError));
    }
}
