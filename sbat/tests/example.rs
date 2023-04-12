// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use sbat::{
    Component, Entry, Metadata, Result, Revocations, SliceVec, ValidationResult,
};

#[test]
fn example() -> Result<()> {
    // Allocate storage for the metadata and revocations. For this
    // example we use a fixed-size slice. If the `alloc` feature is
    // enabled, a `Vec` can be used instead.
    let mut metadata_storage: [Entry; 10] = Default::default();
    let metadata_storage = SliceVec::new(&mut metadata_storage);
    let mut revocation_storage: [Component; 10] = Default::default();
    let revocation_storage = SliceVec::new(&mut revocation_storage);

    // Parse the metadata CSV.
    let mut metadata = Metadata::new(metadata_storage);
    metadata.parse(b"sbat,1,CompA,2")?;

    // Parse the revocations CSV.
    let mut revocations = Revocations::new(revocation_storage);
    revocations.parse(b"sbat,1,2021030218\nCompA,2")?;

    // Check that the metadata is not revoked.
    assert_eq!(
        revocations.validate_metadata(&metadata),
        ValidationResult::Allowed,
    );

    // Change the metadata's CompA generation to 1 and verify that it is
    // revoked.
    metadata.parse(b"sbat,1\nCompA,1")?;
    assert_eq!(
        revocations.validate_metadata(&metadata),
        ValidationResult::Revoked(metadata.entries().last().unwrap()),
    );

    Ok(())
}
