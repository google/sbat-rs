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

use crate::csv::{parse_csv, Record};
use crate::{Component, ParseError, PushError};
use crate::{Entry, ImageSbat};
use ascii::AsciiStr;

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

/// Trait for revocation SBAT.
///
/// Typically this data comes from a UEFI variable such as `SbatLevel`.
pub trait RevocationSbat<'a>: Default {
    /// Date when the data was last updated. This is optional metadata
    /// in the first entry and may not be present.
    fn date(&self) -> Option<&AsciiStr>;

    /// Set the date when the data was last updated.
    fn set_date(&mut self, date: Option<&'a AsciiStr>);

    /// Get the revoked components as a slice. The component version
    /// indicates the lowest *allowed* version of this component; all
    /// lower versions are considered revoked.
    fn revoked_components(&self) -> &[Component<'a>];

    /// Add a revoked component.
    fn try_push(&mut self, component: Component<'a>) -> Result<(), PushError>;

    /// Parse SBAT data from raw CSV. This data typically comes from a
    /// UEFI variable or the `.sbatlevel` section of a shim binary. Each
    /// record is parsed as a [`Component`].
    fn parse(input: &'a [u8]) -> Result<Self, ParseError> {
        let mut revocations = Self::default();

        let mut first = true;

        parse_csv(input, |record: Record<MAX_HEADER_FIELDS>| {
            if first {
                revocations.set_date(record.get_field(2));
                first = false;
            }

            revocations
                .try_push(Component {
                    name: record
                        .get_field(0)
                        .ok_or(ParseError::TooFewFields)?,
                    generation: record
                        .get_field_as_generation(1)?
                        .ok_or(ParseError::TooFewFields)?,
                })
                .map_err(|_| ParseError::TooManyRecords)
        })?;

        Ok(revocations)
    }

    /// Check if any component in `image_sbat` is revoked.
    ///
    /// Each component in the image metadata is checked against the
    /// revocation entries. If the name matches, and if the component's
    /// version is less than the version in the corresponding revocation
    /// entry, the component is considered revoked and the image will
    /// not pass validation. If a component is not in the revocation
    /// list then it is implicitly allowed.
    fn validate_image<I: ImageSbat<'a>>(
        &self,
        image_sbat: &I,
    ) -> ValidationResult<'a> {
        // TODO: move impl to non-generic for code size?

        if let Some(revoked_entry) = image_sbat
            .entries()
            .iter()
            .find(|entry| self.is_component_revoked(&entry.component))
        {
            ValidationResult::Revoked(*revoked_entry)
        } else {
            ValidationResult::Allowed
        }
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
    fn is_component_revoked(&self, input: &Component) -> bool {
        self.revoked_components().iter().any(|revoked_component| {
            input.name == revoked_component.name
                && input.generation < revoked_component.generation
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Generation, ImageSbatArray, RevocationSbatArray, Vendor};

    #[cfg(feature = "alloc")]
    use crate::RevocationSbatVec;

    fn ascii(s: &str) -> &AsciiStr {
        AsciiStr::from_ascii(s).unwrap()
    }

    fn make_component(name: &str, gen: u32) -> Component {
        Component::new(ascii(name), Generation::new(gen).unwrap())
    }

    fn make_entry(name: &str, gen: u32) -> Entry {
        Entry::new(make_component(name, gen), Vendor::default())
    }

    fn make_metadata<'a>(
        components: &'a [Component<'a>],
    ) -> ImageSbatArray<'a, 10> {
        let mut image_sbat = ImageSbatArray::new();
        for comp in components {
            image_sbat
                .try_push(Entry::new(comp.clone(), Vendor::default()))
                .unwrap();
        }

        image_sbat
    }

    fn make_revocations<'a, 'b>(
        data: &'a [Component<'b>],
    ) -> RevocationSbatArray<'b, 10> {
        let mut revocations = RevocationSbatArray::new();

        for elem in data {
            revocations.try_push(elem.clone()).unwrap();
        }

        revocations
    }

    fn parse_success_helper<'a, R: RevocationSbat<'a>>() {
        let input = b"sbat,1,2021030218\ncompA,1\ncompB,2";

        let revocations = R::parse(input).unwrap();

        assert_eq!(revocations.date(), Some(ascii("2021030218")));

        assert_eq!(
            revocations.revoked_components(),
            [
                make_component("sbat", 1),
                make_component("compA", 1),
                make_component("compB", 2)
            ],
        );
    }

    #[test]
    fn parse_success_array() {
        parse_success_helper::<RevocationSbatArray<3>>();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn parse_success_vec() {
        parse_success_helper::<RevocationSbatVec>();
    }

    #[test]
    fn too_few_fields() {
        let input = b"sbat";

        assert_eq!(
            RevocationSbatArray::<2>::parse(input),
            Err(ParseError::TooFewFields)
        );
    }

    #[test]
    fn no_date_field() {
        let input = b"sbat,1";

        let revocations = RevocationSbatArray::<2>::parse(input).unwrap();

        assert!(revocations.date().is_none());

        assert_eq!(
            revocations.revoked_components(),
            [make_component("sbat", 1)]
        );
    }

    #[test]
    fn is_component_revoked() {
        let revocations = make_revocations(&[
            make_component("compA", 2),
            make_component("compB", 3),
        ]);

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

        let revocations = make_revocations(&[
            make_component("compA", 2),
            make_component("compB", 3),
        ]);

        // Invalid component.
        assert_eq!(
            revocations
                .validate_image(&make_metadata(&[make_component("compA", 1)])),
            Revoked(make_entry("compA", 1))
        );

        // compA valid, compB invalid.
        assert_eq!(
            revocations.validate_image(&make_metadata(&[
                make_component("compA", 2),
                make_component("compB", 2),
            ])),
            Revoked(make_entry("compB", 2))
        );

        // compA invalid, compB valid.
        assert_eq!(
            revocations.validate_image(&make_metadata(&[
                make_component("compA", 1),
                make_component("compB", 3),
            ])),
            Revoked(make_entry("compA", 1))
        );

        // compA valid, compB valid.
        assert_eq!(
            revocations.validate_image(&make_metadata(&[
                make_component("compA", 2),
                make_component("compB", 3),
            ])),
            Allowed
        );

        // compC valid.
        assert_eq!(
            revocations
                .validate_image(&make_metadata(&[make_component("compC", 1)])),
            Allowed
        );

        // compC valid, compA invalid.
        assert_eq!(
            revocations.validate_image(&make_metadata(&[
                make_component("compC", 1),
                make_component("compA", 1)
            ])),
            Revoked(make_entry("compA", 1))
        );
    }
}
