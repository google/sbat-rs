// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use sbat::{
    ImageSbat, ImageSbatArray, ParseError, RevocationSbat, RevocationSbatArray,
    ValidationResult,
};

#[test]
fn example() -> Result<(), ParseError> {
    // This example uses fixed-size array types that do not allocate. If
    // the `alloc` feature is enabled, you can use `ImageSbatVec` and
    // `RevocationSbatVec` instead.

    // Parse the image SBAT.
    let image_sbat = ImageSbatArray::<10>::parse(b"sbat,1,CompA,2")?;

    // Parse the revocations SBAT.
    let revocations =
        RevocationSbatArray::<10>::parse(b"sbat,1,2021030218\nCompA,2")?;

    // Check that the image is not revoked.
    assert_eq!(
        revocations.validate_image(&image_sbat),
        ValidationResult::Allowed,
    );

    // Change the image's CompA generation to 1 and verify that it is
    // revoked.
    let image_sbat = ImageSbatArray::<10>::parse(b"sbat,1\nCompA,1")?;
    assert_eq!(
        revocations.validate_image(&image_sbat),
        ValidationResult::Revoked(*image_sbat.entries().last().unwrap()),
    );

    Ok(())
}
