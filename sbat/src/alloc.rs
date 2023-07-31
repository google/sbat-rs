// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Component, Entry, ImageSbat, PushError, RevocationSbat};
use ascii::AsciiStr;
use core::fmt::{self, Display, Formatter};
use rust_alloc::vec::Vec;

/// Image SBAT metadata.
///
/// This contains SBAT entries parsed from the `.sbat` section of a UEFI
/// PE executable.
///
/// See the [crate] documentation for a usage example.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct ImageSbatOwned<'a>(Vec<Entry<'a>>);

impl<'a> ImageSbatOwned<'a> {
    /// Create a new `ImageSbatOwned`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an SBAT entry.
    pub fn push(&mut self, entry: Entry<'a>) {
        self.0.push(entry);
    }
}

impl<'a> ImageSbat<'a> for ImageSbatOwned<'a> {
    fn entries(&self) -> &[Entry<'a>] {
        &self.0
    }

    fn try_push(&mut self, entry: Entry<'a>) -> Result<(), PushError> {
        self.push(entry);
        Ok(())
    }
}

impl<'a> Display for ImageSbatOwned<'a> {
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
pub struct RevocationSbatOwned<'a> {
    date: Option<&'a AsciiStr>,
    components: Vec<Component<'a>>,
}

impl<'a> RevocationSbatOwned<'a> {
    /// Create an empty `RevocationSbatOwned`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a revoked component.
    pub fn push(&mut self, component: Component<'a>) {
        self.components.push(component);
    }
}

impl<'a> RevocationSbat<'a> for RevocationSbatOwned<'a> {
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
        self.push(component);
        Ok(())
    }
}

impl<'a> Display for RevocationSbatOwned<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.to_csv(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        assert_eq!(ImageSbatOwned::new(), ImageSbatOwned::default());
        assert_eq!(RevocationSbatOwned::new(), RevocationSbatOwned::default());
    }
}
