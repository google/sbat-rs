use sbat::{ImageSbat, ImageSbatArray, RevocationSbat, RevocationSbatArray};

#[cfg(feature = "alloc")]
use sbat::{ImageSbatVec, RevocationSbatVec};

const IMAGE_SBAT: &str = "
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,1,Free Software Foundation,grub,2.04,https://www.gnu.org/software/grub/
grub.fedora,2,The Fedora Project,grub2,2.04-32.fc33,https://src.fedoraproject.org/rpms/grub2
";

const REVOCATION_SBAT_1: &str = "
sbat,1
shim,1
grub,3
";

const REVOCATION_SBAT_2: &str = "
sbat,1,2023070812
shim,1
grub,3
";

#[test]
fn test_image_sbat_array_display() {
    let parsed = ImageSbatArray::<3>::parse(IMAGE_SBAT.as_bytes()).unwrap();
    assert_eq!(format!("{parsed}"), IMAGE_SBAT.trim_start());
}

#[cfg(feature = "alloc")]
#[test]
fn test_image_sbat_vec_display() {
    let parsed = ImageSbatVec::parse(IMAGE_SBAT.as_bytes()).unwrap();
    assert_eq!(format!("{parsed}"), IMAGE_SBAT.trim_start());
}

#[test]
fn test_revocation_sbat_array_display() {
    let parsed =
        RevocationSbatArray::<3>::parse(REVOCATION_SBAT_1.as_bytes()).unwrap();
    assert_eq!(format!("{parsed}"), REVOCATION_SBAT_1.trim_start());

    let parsed =
        RevocationSbatArray::<3>::parse(REVOCATION_SBAT_2.as_bytes()).unwrap();
    assert_eq!(format!("{parsed}"), REVOCATION_SBAT_2.trim_start());
}

#[cfg(feature = "alloc")]
#[test]
fn test_revocation_sbat_vec_display() {
    let parsed =
        RevocationSbatVec::parse(REVOCATION_SBAT_1.as_bytes()).unwrap();
    assert_eq!(format!("{parsed}"), REVOCATION_SBAT_1.trim_start());

    let parsed =
        RevocationSbatVec::parse(REVOCATION_SBAT_2.as_bytes()).unwrap();
    assert_eq!(format!("{parsed}"), REVOCATION_SBAT_2.trim_start());
}
