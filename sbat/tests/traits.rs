use sbat::{ImageSbat, ImageSbatArray, RevocationSbat, RevocationSbatArray};

#[test]
fn test_that_traits_are_object_safe() {
    let image_sbat = ImageSbatArray::<1>::new();
    let _: &dyn ImageSbat = &image_sbat;

    let revocation_sbat = RevocationSbatArray::<1>::new();
    let _: &dyn RevocationSbat = &revocation_sbat;
}
