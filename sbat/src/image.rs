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
use crate::{Component, ParseError, PushError};
use ascii::AsciiStr;
use core::fmt::{self, Formatter};

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

/// Trait for image SBAT metadata.
///
/// Typically this data comes from the `.sbat` section of a UEFI PE
/// executable.
pub trait ImageSbat<'a> {
    /// Parse SBAT metadata from raw CSV. This data typically comes from
    /// the `.sbat` section of a UEFI PE executable. Each record is
    /// parsed as an [`Entry`].
    fn parse(input: &'a [u8]) -> Result<Self, ParseError>
    where
        Self: Default,
    {
        let input = trim_ascii_at_null(input)?;

        let mut sbat = Self::default();

        for record in CsvIter::<NUM_ENTRY_FIELDS>::new(input) {
            let record = record?;
            sbat.try_push(Entry::from_record(&record)?)
                .map_err(|_| ParseError::TooManyRecords)?;
        }

        Ok(sbat)
    }

    /// Format as SBAT CSV.
    fn to_csv(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for entry in self.entries() {
            let empty = AsciiStr::from_ascii("").unwrap();

            let comp = &entry.component;
            let vendor = &entry.vendor;
            writeln!(
                f,
                "{},{},{},{},{},{}",
                comp.name,
                comp.generation,
                vendor.name.unwrap_or(empty),
                vendor.package_name.unwrap_or(empty),
                vendor.version.unwrap_or(empty),
                vendor.url.unwrap_or(empty),
            )?;
        }

        Ok(())
    }

    /// Get the SBAT entries.
    fn entries(&self) -> &[Entry<'a>];

    /// Add an SBAT entry.
    fn try_push(&mut self, entry: Entry<'a>) -> Result<(), PushError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use crate::ImageSbatVec;
    use crate::{Generation, ImageSbatArray};

    fn parse_success_helper<'a, I: ImageSbat<'a> + Default>() {
        // The current value of the SBAT data in the shim repo.
        let shim_sbat = b"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,1,UEFI shim,shim,1,https://github.com/rhboot/shim";
        let metadata = I::parse(shim_sbat).unwrap();

        let ascii = |s| AsciiStr::from_ascii(s).unwrap();

        assert_eq!(
            metadata.entries(),
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
        parse_success_helper::<ImageSbatArray<2>>();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn parse_success_vec() {
        parse_success_helper::<ImageSbatVec>();
    }

    #[test]
    fn invalid_record_array() {
        assert_eq!(
            ImageSbatArray::<2>::parse(b"a"),
            Err(ParseError::TooFewFields)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn invalid_record_vec() {
        assert_eq!(ImageSbatVec::parse(b"a"), Err(ParseError::TooFewFields));
    }
}
