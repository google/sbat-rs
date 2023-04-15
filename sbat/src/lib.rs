// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! UEFI SBAT (Secure Boot Advanced Targeting)
//!
//! SBAT is used to revoke insecure UEFI exectuables in a way that won't
//! eat up the limited storage space available in the UEFI environment.
//!
//! There are two important sources of data:
//! 1. The SBAT metadata associated with each image describes the
//!    components in that image.
//! 2. The SBAT revocation data stored in a UEFI variable provides a
//!    list of component versions that are no longer allowed to boot.
//!
//! Each entry in the revocation list contains component name and
//! version fields. (The first entry, which is the sbat version, also
//! has a date field, but it is purely cosmetic.) When validating an
//! image, each component in the image is checked against the revocation
//! entries. If the name matches, and if the component's version is less
//! than the version in the corresponding revocation entry, the
//! component is considered revoked and the image will not pass
//! validation.
//!
//! The details and exact validation rules are described further in the
//! [SBAT.md] and [SBAT.example.md] files in the shim repo.
//!
//! # API
//!
//! This `no_std` library handles parsing both sources of SBAT data
//! (image [`Metadata`] and [`Revocations`] data), as well as performing
//! the revocation comparison. The parsing starts with raw bytes
//! containing the CSV; the library doesn't handle directly reading PE
//! binaries or UEFI variables.
//!
//! # Storage
//!
//! The storage for metadata and revocations is represented by
//! [`Veclike`]. This allows data to be stored in a fixed-sized slice
//! with [`SliceVec`], or in a [`Vec`] if the `alloc` feature is
//! enabled.
//!
//! # Examples
//!
//! ```
#![doc = include_str!("../tests/example.rs")]
//! ```
//!
//! [SBAT.md]: https://github.com/rhboot/shim/blob/HEAD/SBAT.md
//! [SBAT.example.md]: https://github.com/rhboot/shim/blob/HEAD/SBAT.example.md
//! [`Vec`]: https://doc.rust-lang.org/stable/alloc/vec/struct.Vec.html

#![warn(missing_docs)]
// Turn off std, except when running tests.
#![cfg_attr(not(test), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc as rust_alloc;

mod component;
mod csv;
mod generation;
mod image;
mod result;
mod revocations;

#[cfg(feature = "alloc")]
mod alloc;
mod array;

pub use array::{ImageSbatArray, RevocationSbatArray};
pub use component::Component;
pub use csv::ALLOWED_SPECIAL_CHARS;
pub use generation::Generation;
pub use image::{Entry, ImageSbat, Vendor};
pub use result::{Error, Result};
pub use revocations::RevocationSbat;
pub use revocations::ValidationResult;
pub use ValidationResult::{Allowed, Revoked};

#[cfg(feature = "alloc")]
pub use alloc::{ImageSbatVec, RevocationSbatVec};
