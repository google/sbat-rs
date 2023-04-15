// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Simple CSV parser.
//!
//! This parser is restricted in various ways because it is only used
//! for SBAT data, which allows the implementation to be much
//! simpler. In particular:
//!
//! * Only ASCII characters are allowed.
//!
//! * No quoting or escaping is allowed; in addition to alphanumeric
//!   characters only the characters in [`ALLOWED_SPECIAL_CHARS`] are
//!   allowed.
//!
//! * The parser is parameterized over the maximum number of fields in a
//!   record. If a record has more than that number of fields, a warning
//!   is logged but the extra data is ignored. SBAT treats all but the
//!   first two fields in each line as human-readable comments, so
//!   dropping the data is OK.

use crate::{Error, Generation};
use arrayvec::ArrayVec;
use ascii::{AsciiChar, AsciiStr};
use log::warn;

/// ASCII characters that this library allows in SBAT fields (in
/// addition to alphanumeric characters).
pub const ALLOWED_SPECIAL_CHARS: &[AsciiChar] = &[
    AsciiChar::Apostrophe,
    AsciiChar::Asterisk,
    AsciiChar::At,
    AsciiChar::BracketClose,
    AsciiChar::BracketOpen,
    AsciiChar::Caret,
    AsciiChar::Colon,
    AsciiChar::CurlyBraceClose,
    AsciiChar::CurlyBraceClose,
    AsciiChar::CurlyBraceOpen,
    AsciiChar::Dollar,
    AsciiChar::Dot,
    AsciiChar::Exclamation,
    AsciiChar::GreaterThan,
    AsciiChar::Hash,
    AsciiChar::LessThan,
    AsciiChar::Minus,
    AsciiChar::ParenClose,
    AsciiChar::ParenOpen,
    AsciiChar::Plus,
    AsciiChar::Question,
    AsciiChar::Semicolon,
    AsciiChar::Slash,
    AsciiChar::Space,
    AsciiChar::Tilde,
    AsciiChar::UnderScore,
];

fn is_char_allowed_in_field(chr: AsciiChar) -> bool {
    chr.is_alphanumeric() || ALLOWED_SPECIAL_CHARS.contains(&chr)
}

/// Parse a CSV file. The `func` function will be called once for each
/// [`Record`] that is parsed.
pub fn parse_csv<'a, Func, const NUM_FIELDS: usize>(
    input: &'a [u8],
    mut func: Func,
) -> Result<(), Error>
where
    Func: FnMut(Record<'a, NUM_FIELDS>) -> Result<(), Error>,
{
    let input = AsciiStr::from_ascii(input).map_err(|_| Error::InvalidAscii)?;

    for line in input.lines() {
        // Don't return a record for an empty line.
        if line.is_empty() {
            continue;
        }

        let mut record = Record::default();

        for field in line.split(AsciiChar::Comma) {
            // Reject all special characters.
            if let Some(special_char) =
                field.chars().find(|chr| !is_char_allowed_in_field(*chr))
            {
                return Err(Error::SpecialChar(special_char));
            }

            record.add_field(field);
        }

        func(record.clone())?;
        record.0.clear();
    }

    Ok(())
}

/// CSV record. This represents a line of comma-separated fields.
#[derive(Clone, Default)]
pub struct Record<'a, const NUM_FIELDS: usize>(
    ArrayVec<&'a AsciiStr, NUM_FIELDS>,
);

impl<'a, const NUM_FIELDS: usize> Record<'a, NUM_FIELDS> {
    pub fn get_field(&self, index: usize) -> Option<&'a AsciiStr> {
        self.0.get(index).copied()
    }

    /// Get the contents of the record's field at `index` as a
    /// `Generation`.
    pub fn get_field_as_generation(
        &self,
        index: usize,
    ) -> Result<Option<Generation>, Error> {
        if let Some(ascii) = self.get_field(index) {
            Ok(Some(Generation::from_ascii(ascii)?))
        } else {
            Ok(None)
        }
    }

    /// Add a field to the record if possible. If there is no more room,
    /// the error is logged but otherwise ignored. This behavior is used
    /// because SBAT only really cares about the first two fields per
    /// record, the other fields act as human-readable comments.
    fn add_field(&mut self, field: &'a AsciiStr) {
        if self.0.try_push(field).is_err() {
            warn!("maximum fields per record exceeded");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_simple<'a>(s: &'a str) -> Result<Vec<Vec<String>>, Error> {
        const NUM_FIELDS: usize = 3;
        let mut output = Vec::new();
        parse_csv(s.as_bytes(), |record: Record<NUM_FIELDS>| {
            output
                .push(record.0.iter().map(|field| field.to_string()).collect());
            Ok(())
        })?;
        Ok(output)
    }

    #[test]
    fn test_empty() {
        assert!(parse_simple("").unwrap().is_empty());
    }

    #[test]
    fn test_single_field() {
        assert_eq!(parse_simple("ab").unwrap(), [["ab"]]);
    }

    #[test]
    fn test_single_field_with_newline() {
        assert_eq!(parse_simple("ab\n").unwrap(), [["ab"]]);
    }

    #[test]
    fn test_two_fields() {
        assert_eq!(parse_simple("ab,cd").unwrap(), [["ab", "cd"]]);
    }

    #[test]
    fn test_empty_record() {
        assert_eq!(parse_simple("a\n\nb").unwrap(), [["a"], ["b"]]);
    }

    #[test]
    fn test_empty_field() {
        assert_eq!(parse_simple("a,,b").unwrap(), [["a", "", "b"]]);
    }

    #[test]
    fn ignore_extra_fields() {
        assert_eq!(parse_simple("a,b,c,d").unwrap(), [["a", "b", "c"]]);
    }

    #[test]
    fn test_url() {
        assert_eq!(
            parse_simple("http://example.com").unwrap(),
            [["http://example.com"]]
        );
    }

    #[test]
    fn test_special_char() {
        assert_eq!(
            parse_simple("\\"),
            Err(Error::SpecialChar(AsciiChar::BackSlash))
        );
        assert_eq!(
            parse_simple("\""),
            Err(Error::SpecialChar(AsciiChar::Quotation))
        );
    }
}
