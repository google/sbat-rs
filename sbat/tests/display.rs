use sbat::{ImageSbat, ImageSbatArray};

#[cfg(feature = "alloc")]
use sbat::ImageSbatVec;

const IMAGE_SBAT: &str = "
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,1,Free Software Foundation,grub,2.04,https://www.gnu.org/software/grub/
grub.fedora,2,The Fedora Project,grub2,2.04-32.fc33,https://src.fedoraproject.org/rpms/grub2
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
