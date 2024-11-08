// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! SBAT revocations.
//!
//! Typically this data is read from a UEFI variable. See the crate
//! documentation for details of how it is used.

use crate::csv::{trim_ascii_at_null, CsvIter};
use crate::{Component, Entry, ImageSbat, ParseError};
use ascii::AsciiStr;
use core::ptr;

/// The first entry has the component name and generation like the
/// others, but may also have a date field.
const MAX_HEADER_FIELDS: usize = 3;

/// Whether an image is allowed or revoked.
#[must_use]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationResult<'a> {
    /// The image has not been revoked.
    Allowed,

    /// The image has been revoked. The first revoked entry is provided
    /// (there could be additional revoked components).
    Revoked(Entry<'a>),
}

/// Iterator over revoked components in [`RevocationSbat`].
///
/// See [`RevocationSbat::revoked_components`].
pub struct RevokedComponents<'a>(CsvIter<'a, MAX_HEADER_FIELDS>);

impl<'a> Iterator for RevokedComponents<'a> {
    type Item = Component<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.0.next()?;

        // These unwraps will always succeed, because the validity of
        // the data was already checked in RevocationSbat::parse.
        let record = next.unwrap();
        Some(Component::from_record(&record).unwrap())
    }
}

/// Revocation SBAT data.
///
/// Typically this data comes from a UEFI variable such as `SbatLevel`.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct RevocationSbat(AsciiStr);

impl RevocationSbat {
    /// Parse SBAT data from raw CSV. This data typically comes from a
    /// UEFI variable or a [`RevocationSection`]. Each record is parsed
    /// as a [`Component`].
    ///
    /// Any data past the first null in `input` is ignored. A null byte
    /// is not required to be present.
    ///
    /// [`RevocationSection`]: crate::RevocationSection
    pub fn parse(input: &[u8]) -> Result<&Self, ParseError> {
        let input = trim_ascii_at_null(input)?;

        // Ensure that all components are valid.
        let iter = CsvIter::<{ MAX_HEADER_FIELDS }>::new(input);
        for record in iter {
            let record = record?;

            // Check that the first two fields are valid.
            Component::from_record(&record)?;
        }

        Ok(Self::from_ascii_str_unchecked(input))
    }

    /// Internal method to create `&Self` from `&AsciiStr`. This is
    /// essentially a cast, it does not check the validity of the
    /// data. It is only used in the deref implementation for
    /// `RevocationSbatOwned`. Note that although unchecked, this method
    /// is not unsafe; invalid data passed in could lead to a panic, but
    /// no UB.
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

    /// Date of the revocation data, used as a comparable version. This
    /// is optional and may not be present. Versions should be compared
    /// lexographically.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn date(&self) -> Option<&AsciiStr> {
        let mut iter = CsvIter::<{ MAX_HEADER_FIELDS }>::new(&self.0);
        // OK to unwrap: data has already been validated.
        let record = iter.next()?.unwrap();
        record.get_field(2)
    }

    /// Get an iterator over the entries.
    #[must_use]
    pub fn revoked_components(&self) -> RevokedComponents<'_> {
        RevokedComponents(CsvIter::new(&self.0))
    }

    /// Check if the `input` [`Component`] is revoked.
    ///
    /// The `input` is checked against each revocation component. If the
    /// names match, and if the `input`'s version is less than the
    /// version in the corresponding revocation component, the `input`
    /// is considered revoked and the image will not pass validation. If
    /// the `input` is not in the revocation list then it is implicitly
    /// allowed.
    #[must_use]
    pub fn is_component_revoked(&self, input: &Component) -> bool {
        self.revoked_components().any(|revoked_component| {
            input.name == revoked_component.name
                && input.generation < revoked_component.generation
        })
    }

    /// Check if any component in `image_sbat` is revoked.
    ///
    /// Each component in the image metadata is checked against the
    /// revocation entries. If the name matches, and if the component's
    /// version is less than the version in the corresponding revocation
    /// entry, the component is considered revoked and the image will
    /// not pass validation. If a component is not in the revocation
    /// list then it is implicitly allowed.
    pub fn validate_image<'i>(
        &self,
        image_sbat: &'i ImageSbat,
    ) -> ValidationResult<'i> {
        if let Some(revoked_entry) = image_sbat
            .entries()
            .find(|entry| self.is_component_revoked(&entry.component))
        {
            ValidationResult::Revoked(revoked_entry)
        } else {
            ValidationResult::Allowed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Generation, RevocationSbat, Vendor};

    #[cfg(feature = "alloc")]
    use crate::RevocationSbatOwned;

    const VALID_SBAT: &[u8] = b"sbat,1,2021030218\ncompA,1\ncompB,2";

    fn ascii(s: &str) -> &AsciiStr {
        AsciiStr::from_ascii(s).unwrap()
    }

    fn make_component(name: &str, gen: u32) -> Component {
        Component::new(ascii(name), Generation::new(gen).unwrap())
    }

    fn make_entry(name: &str, gen: u32) -> Entry {
        Entry::new(make_component(name, gen), Vendor::default())
    }

    fn parse_success_helper(revocations: &RevocationSbat) {
        assert_eq!(revocations.date(), Some(ascii("2021030218")));
        assert_eq!(
            revocations.revoked_components().collect::<Vec<_>>(),
            [
                make_component("sbat", 1),
                make_component("compA", 1),
                make_component("compB", 2)
            ],
        );
    }

    #[test]
    fn parse_success_array() {
        parse_success_helper(RevocationSbat::parse(VALID_SBAT).unwrap());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn parse_success_vec() {
        parse_success_helper(&RevocationSbatOwned::parse(VALID_SBAT).unwrap());
    }

    #[test]
    fn too_few_fields() {
        let input = b"sbat";

        assert_eq!(RevocationSbat::parse(input), Err(ParseError::TooFewFields));
    }

    #[test]
    fn no_date_field() {
        let input = b"sbat,1";

        let revocations = RevocationSbat::parse(input).unwrap();

        assert!(revocations.date().is_none());

        assert_eq!(
            revocations.revoked_components().collect::<Vec<_>>(),
            [make_component("sbat", 1)]
        );
    }

    #[test]
    fn is_component_revoked() {
        let csv = b"compA,2\ncompB,3";
        let revocations = RevocationSbat::parse(csv).unwrap();

        // compA: anything less than 2 is invalid.
        assert!(revocations.is_component_revoked(&make_component("compA", 1)));
        assert!(!revocations.is_component_revoked(&make_component("compA", 2)));
        assert!(!revocations.is_component_revoked(&make_component("compA", 3)));

        // compB: anything less than 3 is invalid.
        assert!(revocations.is_component_revoked(&make_component("compB", 2)));
        assert!(!revocations.is_component_revoked(&make_component("compB", 3)));
        assert!(!revocations.is_component_revoked(&make_component("compB", 4)));

        // compC: anything is valid.
        assert!(!revocations.is_component_revoked(&make_component("compC", 1)));
        assert!(!revocations.is_component_revoked(&make_component("compC", 2)));
        assert!(!revocations.is_component_revoked(&make_component("compC", 3)));
    }

    #[test]
    fn validate_image() {
        use ValidationResult::{Allowed, Revoked};

        let revocations = RevocationSbat::parse(b"compA,2\ncompB,3").unwrap();

        // Invalid component.
        let image = ImageSbat::parse(b"compA,1").unwrap();
        assert_eq!(
            revocations.validate_image(image),
            Revoked(make_entry("compA", 1))
        );

        // compA valid, compB invalid.
        let image = ImageSbat::parse(b"compA,2\ncompB,2").unwrap();
        assert_eq!(
            revocations.validate_image(image),
            Revoked(make_entry("compB", 2))
        );

        // compA invalid, compB valid.
        let image = ImageSbat::parse(b"compA,1\ncompB,3").unwrap();
        assert_eq!(
            revocations.validate_image(image),
            Revoked(make_entry("compA", 1))
        );

        // compA valid, compB valid.
        let image = ImageSbat::parse(b"compA,2\ncompB,3").unwrap();
        assert_eq!(revocations.validate_image(image), Allowed);

        // compC valid.
        let image = ImageSbat::parse(b"compC,1").unwrap();
        assert_eq!(revocations.validate_image(image), Allowed);

        // compC valid, compA invalid.
        let image = ImageSbat::parse(b"compC,1\ncompA,1").unwrap();
        assert_eq!(
            revocations.validate_image(image),
            Revoked(make_entry("compA", 1))
        );
    }
}
