#![no_main]

use libfuzzer_sys::fuzz_target;
use sbat::{ImageSbat, RevocationSbat};

// Generate both ImageSbat and RevocationSbat so they can be tested
// together.
fuzz_target!(|data: (&[u8], &[u8])| {
    let (image_data, revocation_data) = data;
    if let (Ok(image), Ok(revocations)) = (
        ImageSbat::parse(image_data),
        RevocationSbat::parse(revocation_data),
    ) {
        let _ = image.as_csv();

        let _ = revocations.as_csv();
        let _ = revocations.date();
        for _ in revocations.revoked_components() {}

        let _ = revocations.validate_image(image);
        for entry in image.entries() {
            let _ = revocations.is_component_revoked(&entry.component);
        }
    }
});
