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

use crate::csv::{parse_csv, Record};
use crate::vec::Veclike;
use crate::{Component, Error, Result};
use ascii::AsciiStr;
use core::marker::PhantomData;

/// Vendor data. This is optional human-readable data that is not used
/// for SBAT comparison.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
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
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Entry<'a> {
    /// Component data. This is used for SBAT comparison.
    pub component: Component<'a>,

    /// Vendor data. This is human-readable and not used for SBAT
    /// comparison.
    pub vendor: Vendor<'a>,
}

impl<'a> Entry<'a> {
    const NUM_FIELDS: usize = 6;

    /// Make a new `Entry`.
    pub fn new(component: Component<'a>, vendor: Vendor<'a>) -> Entry<'a> {
        Entry { component, vendor }
    }
}

/// Image SBAT metadata.
///
/// This contains SBAT entries parsed from the `.sbat` section of a UEFI
/// PE executable.
///
/// See the [crate] documentation for a usage example.
#[derive(Debug, Eq, PartialEq)]
pub struct Metadata<'a, Storage: Veclike<Entry<'a>>> {
    entries: Storage,

    /// This is needed for the otherwise-unused 'a lifetime.
    _phantom: PhantomData<Entry<'a>>,
}

impl<'a, Storage> Metadata<'a, Storage>
where
    Storage: Veclike<Entry<'a>>,
{
    /// Create a new `Metadata` using `entries` for storage. Existing
    /// data in `entries` is not cleared.
    pub fn new(entries: Storage) -> Self {
        Self {
            entries,
            _phantom: Default::default(),
        }
    }

    /// Parse SBAT metadata from raw CSV. This data typically comes from
    /// the `.sbat` section of a UEFI PE executable. Each record is
    /// parsed as an [`Entry`].
    ///
    /// Any existing data is cleared before parsing.
    pub fn parse(&mut self, input: &'a [u8]) -> Result<()> {
        self.entries.clear();

        parse_csv(input, |record: Record<{ Entry::NUM_FIELDS }>| {
            self.entries.try_push(Entry::new(
                Component {
                    name: record.get_field(0).ok_or(Error::TooFewFields)?,
                    generation: record
                        .get_field_as_generation(1)?
                        .ok_or(Error::TooFewFields)?,
                },
                Vendor {
                    name: record.get_field(2),
                    package_name: record.get_field(3),
                    version: record.get_field(4),
                    url: record.get_field(5),
                },
            ))
        })
    }

    /// Get the SBAT entries.
    pub fn entries(&self) -> &[Entry<'a>] {
        self.entries.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Generation;
    use arrayvec::ArrayVec;

    #[test]
    fn parse_success() {
        // The current value of the SBAT data in the shim repo.
        let shim_sbat = b"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,1,UEFI shim,shim,1,https://github.com/rhboot/shim";
        let array = ArrayVec::<_, 2>::new();
        let mut metadata = Metadata::new(array);
        metadata.parse(shim_sbat).unwrap();

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
    fn invalid_record() {
        let array = ArrayVec::<_, 2>::new();
        let mut metadata = Metadata::new(array);
        assert_eq!(metadata.parse(b"a"), Err(Error::TooFewFields));
    }

    /// Test that `Metadata::new` does not clear the storage, and test
    /// that `Metadata::parse` does clear the storage.
    #[test]
    fn storage_clear() {
        let mut array = ArrayVec::<_, 2>::new();
        array.push(Entry::default());

        // Initially the input storage has one entry, which should stay
        // true after calling `new`.
        let mut metadata = Metadata::new(array);
        assert_eq!(metadata.entries().len(), 1);

        // Calling parse should clear out the existing data.
        metadata.parse(b"").unwrap();
        assert!(metadata.entries().is_empty());
    }
}
