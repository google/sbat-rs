use sbat::{
    ImageSbat, ImageSbatArray, ParseError, RevocationSbat, RevocationSbatArray,
    ValidationResult,
};
#[cfg(feature = "alloc")]
use sbat::{ImageSbatVec, RevocationSbatVec};

const IMAGE_SBAT_A1: &[u8] = b"sbat,1\nCompA,1";
const IMAGE_SBAT_A2: &[u8] = b"sbat,1\nCompA,2";
const REVOCATION_SBAT: &[u8] = b"sbat,1,2021030218
CompA,2";

/// This example uses fixed-size array types that do not allocate.
#[test]
fn example_fixed_size() -> Result<(), ParseError> {
    // Parse the image and revocation SBAT.
    let image_sbat = ImageSbatArray::<10>::parse(IMAGE_SBAT_A1)?;
    let revocations = RevocationSbatArray::<10>::parse(REVOCATION_SBAT)?;

    // Check that the image is revoked.
    assert_eq!(
        revocations.validate_image(&image_sbat),
        ValidationResult::Revoked(*image_sbat.entries().last().unwrap()),
    );

    // Change the image's CompA generation to 1 and verify that it is no
    // longer revoked.
    let image_sbat = ImageSbatArray::<10>::parse(IMAGE_SBAT_A2)?;
    assert_eq!(
        revocations.validate_image(&image_sbat),
        ValidationResult::Allowed,
    );

    Ok(())
}

/// This example uses `Vec`-like types that dynamically allocate.
#[cfg(feature = "alloc")]
#[test]
fn example_vec() -> Result<(), ParseError> {
    // Parse the image and revocation SBAT.
    let image_sbat = ImageSbatVec::parse(IMAGE_SBAT_A1)?;
    let revocations = RevocationSbatVec::parse(REVOCATION_SBAT)?;

    // Check that the image is revoked.
    assert_eq!(
        revocations.validate_image(&image_sbat),
        ValidationResult::Revoked(*image_sbat.entries().last().unwrap()),
    );

    // Change the image's CompA generation to 1 and verify that it is no
    // longer revoked.
    let image_sbat = ImageSbatVec::parse(IMAGE_SBAT_A2)?;
    assert_eq!(
        revocations.validate_image(&image_sbat),
        ValidationResult::Allowed,
    );

    Ok(())
}
