// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::fmt::{self, Display, Formatter};
use core::mem;

/// Name of the revocation section embedded in shim executables.
///
/// See [`RevocationSection`] for details of this section.
pub const REVOCATION_SECTION_NAME: &str = ".sbatlevel";

/// Error returned by [`RevocationSection::parse`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationSectionError {
    /// The section is not big enough to contain the version field.
    MissingVersion,

    /// The section's version is not 0.
    InvalidVersion(u32),

    /// The section is not big enough to contain the payload header.
    MissingHeader,

    /// The offset of the previous revocation data is invalid.
    InvalidPreviousOffset(u32),

    /// The offset of the latest revocation data is invalid.
    InvalidLatestOffset(u32),

    /// The previous revocation data is not null-terminated.
    MissingPreviousNull,

    /// The latest revocation data is not null-terminated.
    MissingLatestNull,
}

impl Display for RevocationSectionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVersion => {
                write!(f, "missing version field")
            }
            Self::InvalidVersion(version) => {
                write!(f, "invalid version: {version}")
            }
            Self::MissingHeader => {
                write!(f, "missing payload header")
            }
            Self::InvalidPreviousOffset(offset) => {
                write!(f, "invalid previous offset: {offset}")
            }
            Self::InvalidLatestOffset(offset) => {
                write!(f, "invalid latest offset: {offset}")
            }
            Self::MissingPreviousNull => {
                write!(f, "missing null terminator for previous data")
            }
            Self::MissingLatestNull => {
                write!(f, "missing null terminator for latest data")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RevocationSectionError {}

/// Revocation data embedded in the `.sbatlevel` section of a shim executable.
///
/// This section was [added to shim in version 15.7][pr] so that the
/// revocation data can be inspected by code outside of shim.
///
/// # Data format
///
/// The section starts with three [`u32`] fields:
/// * Version (currently always zero)
/// * Previous offset
/// * Latest offset
///
/// The previous and latest offsets point to null-terminated strings in
/// the section. The offsets are relative to the end of the version
/// field (so four bytes after the start of the section).
///
/// The previous and latest strings are CSV-formatted revocation data
/// that can be parsed with [`RevocationSbat::parse`].
///
/// [pr]: https://github.com/rhboot/shim/pull/483
/// [`RevocationSbat::parse`]: crate::RevocationSbat::parse
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationSection<'a> {
    previous: &'a [u8],
    latest: &'a [u8],
}

impl<'a> RevocationSection<'a> {
    /// Parse `RevocationSection` from raw data.
    ///
    /// Typically this data is read from the `.sbatlevel` section of a
    /// shim executable.
    #[allow(clippy::missing_panics_doc)]
    pub fn parse(
        mut data: &'a [u8],
    ) -> Result<RevocationSection, RevocationSectionError> {
        const PAYLOAD_HEADER_SIZE: usize = mem::size_of::<u32>() * 2;

        let version_size = mem::size_of::<u32>();
        if data.len() < version_size {
            return Err(RevocationSectionError::MissingVersion);
        }
        let version =
            u32::from_le_bytes(data[..version_size].try_into().unwrap());
        if version != 0 {
            return Err(RevocationSectionError::InvalidVersion(version));
        }

        data = &data[version_size..];
        if data.len() < PAYLOAD_HEADER_SIZE {
            return Err(RevocationSectionError::MissingHeader);
        }

        let previous_offset = u32::from_le_bytes(data[..4].try_into().unwrap());
        let latest_offset = u32::from_le_bytes(data[4..8].try_into().unwrap());

        let previous_start =
            usize::try_from(previous_offset).map_err(|_| {
                RevocationSectionError::InvalidPreviousOffset(previous_offset)
            })?;
        let latest_start = usize::try_from(latest_offset).map_err(|_| {
            RevocationSectionError::InvalidLatestOffset(latest_offset)
        })?;

        if previous_start >= data.len() {
            return Err(RevocationSectionError::InvalidPreviousOffset(
                previous_offset,
            ));
        }
        if latest_start >= data.len() {
            return Err(RevocationSectionError::InvalidLatestOffset(
                latest_offset,
            ));
        }

        let previous_len = data[previous_start..]
            .iter()
            .position(|b| *b == 0)
            .ok_or(RevocationSectionError::MissingPreviousNull)?;
        let latest_len = data[latest_start..]
            .iter()
            .position(|b| *b == 0)
            .ok_or(RevocationSectionError::MissingLatestNull)?;

        let previous = &data
            [previous_start..previous_start.checked_add(previous_len).unwrap()];
        let latest =
            &data[latest_start..latest_start.checked_add(latest_len).unwrap()];

        Ok(Self { previous, latest })
    }

    /// Get the raw previous revocation data.
    ///
    /// This data be parsed with [`RevocationSbat::parse`].
    ///
    /// [`RevocationSbat::parse`]: crate::RevocationSbat::parse
    #[must_use]
    pub fn previous(&self) -> &[u8] {
        self.previous
    }

    /// Get the raw latest revocation data.
    ///
    /// This data be parsed with [`RevocationSbat::parse`].
    ///
    /// [`RevocationSbat::parse`]: crate::RevocationSbat::parse
    #[must_use]
    pub fn latest(&self) -> &[u8] {
        self.latest
    }
}
