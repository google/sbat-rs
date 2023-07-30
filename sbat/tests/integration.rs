// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This file tests the SBAT library using the examples from:
//! <https://github.com/rhboot/shim/blob/899314b90113abaaa4b22cd1d82a0fcb2a971850/SBAT.example.md>

use sbat::{Allowed, ImageSbat, RevocationSbat, Revoked};

// Initial data.

const REVOCATIONS_INITIAL: &[u8] = b"
sbat,1
shim,1
grub,1
grub.fedora,1
";

const GRUB_VANILLA_INITIAL: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,1,Free Software Foundation,grub,2.04,https://www.gnu.org/software/grub/
";

const GRUB_FEDORA_INITIAL: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,1,Free Software Foundation,grub,2.04,https://www.gnu.org/software/grub/
grub.fedora,1,The Fedora Project,grub2,2.04-31.fc33,https://src.fedoraproject.org/rpms/grub2
";

const GRUB_REDHAT_INITIAL: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,1,Free Software Foundation,grub,2.02,https://www.gnu.org/software/grub/
grub.fedora,1,Red Hat Enterprise Linux,grub2,2.02-0.34.fc24,mail:secalert@redhat.com
grub.rhel,1,Red Hat Enterprise Linux,grub2,2.02-0.34.el7_2,mail:secalert@redhat.com
";

const GRUB_DEBIAN_INITIAL: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,1,Free Software Foundation,grub,2.04,https://www.gnu.org/software/grub/
grub.debian,1,Debian,grub2,2.04-12,https://packages.debian.org/source/sid/grub2
";

const GRUB_ACME_INITIAL: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub.acme,1,Acme Corporation,grub,1.96-8191,https://acme.arpa/packages/grub
";

// Bug 0.

const REVOCATIONS_BUG0: &[u8] = b"
sbat,1
shim,1
grub,1
grub.fedora,2
";

const GRUB_FEDORA_BUG0: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,1,Free Software Foundation,grub,2.04,https://www.gnu.org/software/grub/
grub.fedora,2,The Fedora Project,grub2,2.04-32.fc33,https://src.fedoraproject.org/rpms/grub2
";

const GRUB_REDHAT_BUG0: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,1,Free Software Foundation,grub,2.02,https://www.gnu.org/software/grub/
grub.fedora,2,Red Hat Enterprise Linux,grub2,2.02-0.34.fc24,mail:secalert@redhat.com
grub.rhel,2,Red Hat Enterprise Linux,grub2,2.02-0.34.el7_2.1,mail:secalert@redhat.com
";

// Bug 1.

const REVOCATIONS_BUG1: &[u8] = b"
sbat,1
shim,1
grub,2
grub.fedora,2
";

const GRUB_VANILLA_BUG1: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,2,Free Software Foundation,grub,2.05,https://www.gnu.org/software/grub/
";

const GRUB_FEDORA_BUG1: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,2,Free Software Foundation,grub,2.04,https://www.gnu.org/software/grub/
grub.fedora,2,The Fedora Project,grub2,2.04-33.fc33,https://src.fedoraproject.org/rpms/grub2
";

const GRUB_ACME_BUG1: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,2,Free Software Foundation,grub,1.96,https://www.gnu.org/software/grub/
grub.acme,2,Acme Corporation,grub,1.96-8192,https://acme.arpa/packages/grub
";

// Acme updates to grub 2.

const GRUB_ACME_V2: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,2,Free Software Foundation,grub,2.05,https://www.gnu.org/software/grub/
grub.acme,2,Acme Corporation,grub,2.05-1,https://acme.arpa/packages/grub
";

// Bug 2.

const REVOCATIONS_BUG2: &[u8] = b"
sbat,1
shim,1
grub,3
grub.fedora,2
";

// Note: changed grub,1 to grub,2 here.
const GRUB_DEBIAN_BUG2_1: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,2,Free Software Foundation,grub,2.04,https://www.gnu.org/software/grub/
grub.debian,2,Debian,grub2,2.04-13,https://packages.debian.org/source/sid/grub2
";

const GRUB_DEBIAN_BUG2_2: &[u8] = b"
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,3,Free Software Foundation,grub,2.04,https://www.gnu.org/software/grub/
grub.debian,2,Debian,grub2,2.04-13,https://packages.debian.org/source/sid/grub2
";

#[test]
fn initial() {
    // Initially, nothing is revoked.
    assert_allowed(REVOCATIONS_INITIAL, GRUB_VANILLA_INITIAL);
    assert_allowed(REVOCATIONS_INITIAL, GRUB_FEDORA_INITIAL);
    assert_allowed(REVOCATIONS_INITIAL, GRUB_REDHAT_INITIAL);
    assert_allowed(REVOCATIONS_INITIAL, GRUB_DEBIAN_INITIAL);
    assert_allowed(REVOCATIONS_INITIAL, GRUB_ACME_INITIAL);
}

#[test]
fn bug0() {
    // Previous revocations don't effect updated images.
    assert_allowed(REVOCATIONS_INITIAL, GRUB_FEDORA_BUG0);
    assert_allowed(REVOCATIONS_INITIAL, GRUB_REDHAT_BUG0);

    // Updated revocations do affect the old images.
    assert_revoked(REVOCATIONS_BUG0, GRUB_FEDORA_INITIAL);
    assert_revoked(REVOCATIONS_BUG0, GRUB_REDHAT_INITIAL);

    // Updated revocations allow the updated images.
    assert_allowed(REVOCATIONS_BUG0, GRUB_FEDORA_BUG0);
    assert_allowed(REVOCATIONS_BUG0, GRUB_REDHAT_BUG0);
}

#[test]
fn bug1() {
    // Previous revocations don't effect updated images.
    assert_allowed(REVOCATIONS_BUG0, GRUB_VANILLA_BUG1);
    assert_allowed(REVOCATIONS_BUG0, GRUB_FEDORA_BUG1);
    assert_allowed(REVOCATIONS_BUG0, GRUB_ACME_BUG1);

    // Updated revocations do affect the old images.
    assert_revoked(REVOCATIONS_BUG1, GRUB_VANILLA_INITIAL);
    assert_revoked(REVOCATIONS_BUG1, GRUB_FEDORA_BUG0);
    // TODO(nicholasbishop): pretty sure this is a bug in the doc, it
    // should be revoked too. Will file a shim issue for this.
    assert_allowed(REVOCATIONS_BUG1, GRUB_ACME_INITIAL);

    // Updated revocations allow the updated images.
    assert_allowed(REVOCATIONS_BUG1, GRUB_VANILLA_BUG1);
    assert_allowed(REVOCATIONS_BUG1, GRUB_FEDORA_BUG1);
    assert_allowed(REVOCATIONS_BUG1, GRUB_ACME_BUG1);
}

#[test]
fn acme_updates_to_v2() {
    // Previous image is allowed, and so is the new image.
    assert_allowed(REVOCATIONS_BUG1, GRUB_ACME_BUG1);
    assert_allowed(REVOCATIONS_BUG1, GRUB_ACME_V2);
}

#[test]
fn bug2() {
    // Previous revocations don't affect either of the update images.
    assert_allowed(REVOCATIONS_BUG1, GRUB_DEBIAN_BUG2_1);
    assert_allowed(REVOCATIONS_BUG1, GRUB_DEBIAN_BUG2_2);

    // Updated revocations do affect old images.
    assert_revoked(REVOCATIONS_BUG2, GRUB_DEBIAN_INITIAL);

    // Updated revocations affect the intermediate image.
    assert_revoked(REVOCATIONS_BUG2, GRUB_DEBIAN_BUG2_1);

    // Updated revocations allow the final image.
    assert_allowed(REVOCATIONS_BUG2, GRUB_DEBIAN_BUG2_2);
}

fn assert_revoked(revocations_csv: &[u8], metadata_csv: &[u8]) {
    let revocations = RevocationSbat::parse(revocations_csv).unwrap();
    let image_sbat = ImageSbat::parse(metadata_csv).unwrap();

    assert!(matches!(
        revocations.validate_image(&image_sbat),
        Revoked(_)
    ));
}

fn assert_allowed(revocations_csv: &[u8], metadata_csv: &[u8]) {
    let revocations = RevocationSbat::parse(revocations_csv).unwrap();
    let image_sbat = ImageSbat::parse(metadata_csv).unwrap();

    assert_eq!(revocations.validate_image(&image_sbat), Allowed);
}
