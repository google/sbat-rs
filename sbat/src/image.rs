// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! SBAT metadata associated with an executable.
//!
//! Typically this data is read from the `.sbat` section of a UEFI PE
//! executable. See the crate documentation for details of how it is
//! used.

use crate::csv::{trim_ascii_at_null, CsvIter, Record};
use crate::{Component, ParseError};
use ascii::AsciiStr;
use core::ptr;

/// Standard PE section name for SBAT metadata.
pub const SBAT_SECTION_NAME: &str = ".sbat";

/// Vendor data. This is optional human-readable data that is not used
/// for SBAT comparison.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Vendor<'a> {
    /// Human-readable vendor name.
    pub name: Option<&'a AsciiStr>,

    /// Human-readable package name.
    pub package_name: Option<&'a AsciiStr>,

    /// Human-readable package version.
    pub version: Option<&'a AsciiStr>,

    /// Url to look stuff up, contact, etc.
    pub url: Option<&'a AsciiStr>,
}

/// Entry in image SBAT metadata. This contains a [`Component`], which
/// is what gets used for revocation comparisons, as well as [`Vendor`]
/// data, which is extra data that serves as a human-readable comment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Entry<'a> {
    /// Component data. This is used for SBAT comparison.
    pub component: Component<'a>,

    /// Vendor data. This is human-readable and not used for SBAT
    /// comparison.
    pub vendor: Vendor<'a>,
}

const NUM_ENTRY_FIELDS: usize = 6;

impl<'a> Entry<'a> {
    /// Make a new `Entry`.
    #[must_use]
    pub fn new(component: Component<'a>, vendor: Vendor<'a>) -> Entry<'a> {
        Entry { component, vendor }
    }

    /// Parse an `Entry` from a `Record`.
    fn from_record(
        record: &Record<'a, NUM_ENTRY_FIELDS>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(
            Component::from_record(record)?,
            Vendor {
                name: record.get_field(2),
                package_name: record.get_field(3),
                version: record.get_field(4),
                url: record.get_field(5),
            },
        ))
    }
}

/// Iterator over entries in [`ImageSbat`].
///
/// See [`ImageSbat::entries`].
pub struct Entries<'a>(CsvIter<'a, NUM_ENTRY_FIELDS>);

impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.0.next()?;

        // These unwraps will always succeed, because the validity of
        // the data was already checked in ImageSbat::parse.
        let record = next.unwrap();
        Some(Entry::from_record(&record).unwrap())
    }
}

/// Image SBAT metadata.
///
/// Typically this data comes from the `.sbat` section of a UEFI PE
/// executable.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct ImageSbat(AsciiStr);

impl ImageSbat {
    /// Parse SBAT metadata from raw CSV. This data typically comes from
    /// the `.sbat` section of a UEFI PE executable. Each record is
    /// parsed as an [`Entry`].
    ///
    /// Any data past the first null in `input` is ignored. A null byte
    /// is not required to be present.
    pub fn parse(input: &[u8]) -> Result<&Self, ParseError> {
        let input = trim_ascii_at_null(input)?;

        // Ensure that all entries are valid.
        let iter = CsvIter::<NUM_ENTRY_FIELDS>::new(input);
        for record in iter {
            let record = record?;
            // Check that the first two fields are valid. The other
            // fields are optional.
            Component::from_record(&record)?;
        }

        Ok(Self::from_ascii_str_unchecked(input))
    }

    /// Internal method to create `&Self` from `&AsciiStr`. This is
    /// essentially a cast, it does not check the validity of the
    /// data. It is only used in the deref implementation for
    /// `ImageSbatOwned`. Note that although unchecked, this method is
    /// not unsafe; invalid data passed in could lead to a panic, but no
    /// UB.
    #[allow(unsafe_code)]
    pub(crate) fn from_ascii_str_unchecked(s: &AsciiStr) -> &Self {
        // SAFETY: `Self` is a `repr(transparent)` wrapper around
        // `AsciiStr`, so the types are compatible.
        unsafe { &*(ptr::from_ref(s) as *const Self) }
    }

    /// Get the underlying ASCII CSV string.
    #[must_use]
    pub fn as_csv(&self) -> &AsciiStr {
        &self.0
    }

    /// Get an iterator over the entries.
    #[must_use]
    pub fn entries(&self) -> Entries<'_> {
        Entries(CsvIter::new(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Generation;

    #[cfg(feature = "alloc")]
    use crate::ImageSbatOwned;

    const VALID_SBAT: &[u8] = b"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,1,UEFI shim,shim,1,https://github.com/rhboot/shim";

    fn parse_success_helper(image_sbat: &ImageSbat) {
        let ascii = |s| AsciiStr::from_ascii(s).unwrap();

        assert_eq!(
            image_sbat.entries().collect::<Vec<_>>(),
            [
                Entry::new(
                    Component {
                        name: ascii("sbat"),
                        generation: Generation::new(1).unwrap(),
                    },
                    Vendor {
                        name: Some(ascii("SBAT Version")),
                        package_name: Some(ascii("sbat")),
                        version: Some(ascii("1")),
                        url: Some(ascii(
                            "https://github.com/rhboot/shim/blob/main/SBAT.md"
                        )),
                    },
                ),
                Entry::new(
                    Component {
                        name: ascii("shim"),
                        generation: Generation::new(1).unwrap(),
                    },
                    Vendor {
                        name: Some(ascii("UEFI shim")),
                        package_name: Some(ascii("shim")),
                        version: Some(ascii("1")),
                        url: Some(ascii("https://github.com/rhboot/shim")),
                    }
                )
            ]
        );
    }

    #[test]
    fn parse_success_array() {
        parse_success_helper(ImageSbat::parse(VALID_SBAT).unwrap());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn parse_success_vec() {
        parse_success_helper(&ImageSbatOwned::parse(VALID_SBAT).unwrap());
    }

    #[test]
    fn invalid_record_array() {
        assert_eq!(ImageSbat::parse(b"a"), Err(ParseError::TooFewFields));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn invalid_record_vec() {
        assert_eq!(ImageSbatOwned::parse(b"a"), Err(ParseError::TooFewFields));
    }
}
