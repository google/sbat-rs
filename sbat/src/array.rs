// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Component, Entry, Error, ImageSbat, RevocationSbat};
use arrayvec::ArrayVec;
use ascii::AsciiStr;

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
    pub fn new() -> Self {
        Self::default()
    }
}

impl<'a, const N: usize> ImageSbat<'a> for ImageSbatArray<'a, N> {
    fn entries(&self) -> &[Entry<'a>] {
        &self.0
    }

    fn try_push(&mut self, entry: Entry<'a>) -> Result<(), Error> {
        self.0.try_push(entry).map_err(|_| Error::TooManyRecords)
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

    fn try_push(&mut self, component: Component<'a>) -> Result<(), Error> {
        self.components
            .try_push(component)
            .map_err(|_| Error::TooManyRecords)
    }
}
