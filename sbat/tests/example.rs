use sbat::{ImageSbat, ParseError, RevocationSbat, ValidationResult};

fn main() -> Result<(), ParseError> {
    let image_sbat_a1 = b"sbat,1\nCompA,1";
    let image_sbat_a2 = b"sbat,1\nCompA,2";
    let revocation_sbat = b"sbat,1,2021030218\nCompA,2";

    // Parse the image and revocation SBAT.
    let image_sbat = ImageSbat::parse(image_sbat_a1)?;
    let revocations = RevocationSbat::parse(revocation_sbat)?;

    // Check that the image is revoked.
    assert_eq!(
        revocations.validate_image(image_sbat),
        ValidationResult::Revoked(image_sbat.entries().last().unwrap()),
    );

    // Change the image's CompA generation to 2 and verify that it is no
    // longer revoked.
    let image_sbat = ImageSbat::parse(image_sbat_a2)?;
    assert_eq!(
        revocations.validate_image(image_sbat),
        ValidationResult::Allowed,
    );

    Ok(())
}
