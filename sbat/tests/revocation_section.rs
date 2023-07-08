use sbat::{RevocationSbat, RevocationSection, RevocationSectionError};

#[cfg(feature = "alloc")]
use sbat::RevocationSbatVec;

/// Parse the actual `.sbatlevel` data in shim as of 2023-01-29.
#[cfg(feature = "alloc")]
#[test]
fn test_actual_sbatlevel_data() {
    let data = include_bytes!("sbatlevel.section");
    let sbat_level_section = RevocationSection::parse(data).unwrap();
    assert_eq!(
        sbat_level_section.previous(),
        b"sbat,1,2022052400\ngrub,2\n"
    );
    assert_eq!(
        sbat_level_section.latest(),
        b"sbat,1,2023012900\nshim,2\ngrub,3\ngrub.debian,4\n"
    );

    // Check that the revocation data parses.
    RevocationSbatVec::parse(sbat_level_section.previous()).unwrap();
    RevocationSbatVec::parse(sbat_level_section.latest()).unwrap();

    // Check equality despite extra trailing data.
    let mut data = data.to_vec();
    data.push(123);
    let sbat_level_section2 = RevocationSection::parse(&data).unwrap();
    assert_eq!(sbat_level_section, sbat_level_section2);
}

#[test]
fn test_sbat_level_section_errors() {
    assert_eq!(
        RevocationSection::parse(&[0, 0, 0]),
        Err(RevocationSectionError::MissingVersion)
    );

    assert_eq!(
        RevocationSection::parse(&[1, 0, 0, 0]),
        Err(RevocationSectionError::InvalidVersion(1))
    );

    assert_eq!(
        RevocationSection::parse(&[0; 11]),
        Err(RevocationSectionError::MissingHeader)
    );

    #[rustfmt::skip]
    let data = [
        // Version.
        0, 0, 0, 0,
        // Previous offset.
        8, 0, 0, 0,
        // Latest offset.
        8, 0, 0, 0,
    ];
    assert_eq!(
        RevocationSection::parse(&data),
        Err(RevocationSectionError::InvalidPreviousOffset(8))
    );

    #[rustfmt::skip]
    let data = [
        // Version.
        0, 0, 0, 0,
        // Previous offset.
        8, 0, 0, 0,
        // Latest offset.
        9, 0, 0, 0,
        // Previous data.
        0,
    ];
    assert_eq!(
        RevocationSection::parse(&data),
        Err(RevocationSectionError::InvalidLatestOffset(9))
    );

    #[rustfmt::skip]
    let data = [
        // Version.
        0, 0, 0, 0,
        // Previous offset.
        8, 0, 0, 0,
        // Latest offset.
        8, 0, 0, 0,
        // Previous data.
        1,
    ];
    assert_eq!(
        RevocationSection::parse(&data),
        Err(RevocationSectionError::MissingPreviousNull),
    );

    #[rustfmt::skip]
    let data = [
        // Version.
        0, 0, 0, 0,
        // Previous offset.
        8, 0, 0, 0,
        // Latest offset.
        9, 0, 0, 0,
        // Previous data.
        0,
        // Latest data.
        1,
    ];
    assert_eq!(
        RevocationSection::parse(&data),
        Err(RevocationSectionError::MissingLatestNull),
    );
}
