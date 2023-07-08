use sbat::{ImageSbat, ImageSbatArray};

#[test]
fn test_that_traits_are_object_safe() {
    let image_sbat = ImageSbatArray::<1>::new();
    let _: &dyn ImageSbat = &image_sbat;
}
