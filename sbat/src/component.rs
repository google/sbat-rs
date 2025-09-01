// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::csv::Record;
use crate::{Generation, ParseError};
use ascii::AsciiStr;

/// SBAT component. This is the machine-readable portion of SBAT that is
/// actually used for revocation (other fields are human-readable and
/// not used for comparisons).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Component<'a> {
    /// Component name.
    pub name: &'a AsciiStr,

    /// Component generation.
    pub generation: Generation,
}

impl<'a> Component<'a> {
    /// Create a `Component`.
    #[must_use]
    pub fn new(name: &'a AsciiStr, generation: Generation) -> Self {
        Self { name, generation }
    }

    /// Parse a `Component` from a `Record`.
    pub(crate) fn from_record<const N: usize>(
        record: &Record<'a, N>,
    ) -> Result<Self, ParseError> {
        Ok(Self {
            name: record.get_field(0).ok_or(ParseError::TooFewFields)?,
            generation: record
                .get_field_as_generation(1)?
                .ok_or(ParseError::TooFewFields)?,
        })
    }
}
