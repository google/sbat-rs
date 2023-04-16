// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::ParseError;
use ascii::AsciiStr;
use core::fmt::{self, Display, Formatter};
use core::str::FromStr;

/// SBAT component generation.
///
/// This is the machine-comparable version number of a component. It is
/// always a positive integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Generation(u32);

impl Default for Generation {
    fn default() -> Generation {
        Generation(1)
    }
}

impl Generation {
    /// Create a `Generation` from a [`u32`]. An error is returned if
    /// the input is zero.
    pub fn new(val: u32) -> Result<Self, ParseError> {
        if val == 0 {
            Err(ParseError::InvalidGeneration)
        } else {
            Ok(Self(val))
        }
    }

    /// Parse an ASCII string as a `Generation`.
    pub fn from_ascii(s: &AsciiStr) -> Result<Self, ParseError> {
        let val = u32::from_str(s.as_str())
            .map_err(|_| ParseError::InvalidGeneration)?;
        Self::new(val)
    }

    /// Get the generation value as a [`u32`].
    pub fn to_u32(self) -> u32 {
        self.0
    }
}

impl Display for Generation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generation() {
        assert_eq!(Generation::default(), Generation::new(1).unwrap());
        assert_eq!(
            Generation::from_ascii(AsciiStr::from_ascii("123").unwrap())
                .unwrap()
                .to_u32(),
            123
        );
        assert_eq!(Generation::default().to_string(), "1");
    }
}
