// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use ascii::AsciiChar;
use core::fmt::{self, Display, Formatter};

/// SBAT parse error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// CSV field is not ASCII. According to the SBAT spec, all fields
    /// must be ASCII.
    InvalidAscii,

    /// CSV field contains a special character. The characters allowed
    /// are alphabetic, numeric, and [`ALLOWED_SPECIAL_CHARS`]. This is
    /// to keep parsing simple. In particular, double-quote and escape
    /// characters are not allowed, so a field cannot contain a comma.
    ///
    /// [`ALLOWED_SPECIAL_CHARS`]: crate::ALLOWED_SPECIAL_CHARS
    SpecialChar(AsciiChar),

    /// CSV field is not a valid [`Generation`] number.
    ///
    /// [`Generation`]: crate::Generation
    InvalidGeneration,

    /// CSV has more records than allowed.
    TooManyRecords,

    /// CSV record has too few fields.
    TooFewFields,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAscii => write!(f, "CSV field is not ASCII"),
            Self::SpecialChar(c) => {
                write!(
                    f,
                    "CSV field contains special character: {:#04x}",
                    c.as_byte()
                )
            }
            Self::InvalidGeneration => {
                write!(f, "invalid generation, must be a positive integer")
            }
            Self::TooManyRecords => write!(
                f,
                "the output storage is too small to contain the parsed CSV"
            ),
            Self::TooFewFields => {
                write!(f, "a CSV record does not have enough fields")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

/// Error returned by `try_push` if the underlying storage is out of space.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushError;

impl Display for PushError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "the underlying storage is out of space")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PushError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", ParseError::SpecialChar(AsciiChar::Null)),
            "CSV field contains special character: 0x00"
        );
    }
}
