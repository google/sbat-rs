// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{ImageSbat, ParseError, RevocationSbat};
use ascii::AsciiString;
use core::ops::Deref;

/// Owned image SBAT metadata.
///
/// Typically this data comes from the `.sbat` section of a UEFI PE
/// executable.
///
/// This type is the owned version of [`ImageSbat`], and derefs to that
/// type.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ImageSbatOwned(AsciiString);

impl ImageSbatOwned {
    /// Parse SBAT metadata from raw CSV. This data typically comes from
    /// the `.sbat` section of a UEFI PE executable. Each record is
    /// parsed as an [`Entry`].
    ///
    /// Any data past the first null in `input` is ignored. A null byte
    /// is not required to be present.
    ///
    /// [`Entry`]: crate::Entry
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        let sbat = ImageSbat::parse(input)?;
        Ok(Self(sbat.as_csv().to_ascii_string()))
    }
}

impl Deref for ImageSbatOwned {
    type Target = ImageSbat;

    fn deref(&self) -> &Self::Target {
        ImageSbat::from_ascii_str_unchecked(&self.0)
    }
}

impl PartialEq<&ImageSbat> for ImageSbatOwned {
    fn eq(&self, other: &&ImageSbat) -> bool {
        &**self == *other
    }
}

impl PartialEq<ImageSbatOwned> for &ImageSbat {
    fn eq(&self, other: &ImageSbatOwned) -> bool {
        *self == &**other
    }
}

/// Owned revocation SBAT data.
///
/// Typically this data comes from a UEFI variable such as `SbatLevel`.
///
/// This type is the owned version of [`RevocationSbat`], and derefs to
/// that type.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RevocationSbatOwned(AsciiString);

impl RevocationSbatOwned {
    /// Parse SBAT data from raw CSV. This data typically comes from a
    /// UEFI variable or a [`RevocationSection`]. Each record is parsed
    /// as a [`Component`].
    ///
    /// Any data past the first null in `input` is ignored. A null byte
    /// is not required to be present.
    ///
    /// [`Component`]: crate::Component
    /// [`RevocationSection`]: crate::RevocationSection
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        let sbat = RevocationSbat::parse(input)?;
        Ok(Self(sbat.as_csv().to_ascii_string()))
    }
}

impl Deref for RevocationSbatOwned {
    type Target = RevocationSbat;

    fn deref(&self) -> &Self::Target {
        RevocationSbat::from_ascii_str_unchecked(&self.0)
    }
}

impl PartialEq<&RevocationSbat> for RevocationSbatOwned {
    fn eq(&self, other: &&RevocationSbat) -> bool {
        &**self == *other
    }
}

impl PartialEq<RevocationSbatOwned> for &RevocationSbat {
    fn eq(&self, other: &RevocationSbatOwned) -> bool {
        *self == &**other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &[u8] = b"compA,1\ncompB,2\ncompC,3";

    #[test]
    fn test_image_sbat_owned() {
        let r1 = ImageSbat::parse(CSV).unwrap();
        let r2 = ImageSbatOwned::parse(CSV).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(r2, r1);
    }

    #[test]
    fn test_revocation_sbat_owned() {
        let r1 = RevocationSbat::parse(CSV).unwrap();
        let r2 = RevocationSbatOwned::parse(CSV).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(r2, r1);
    }
}
