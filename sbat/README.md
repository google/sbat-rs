# sbat

[![Crates.io](https://img.shields.io/crates/v/sbat)](https://crates.io/crates/sbat)
[![Docs.rs](https://docs.rs/sbat/badge.svg)](https://docs.rs/sbat)

This no-std library handles [SBAT][SBAT.md] parsing and SBAT revocation
checks.

SBAT is a space-efficient method of revoking boot privileges from UEFI
executables when secure boot is enabled. There are two sources of data
needed for SBAT: metadata associated with the image being booted, and a
revocation list.

## Image metadata

Executables (like shim and grub) get SBAT data embedded in a special
`.sbat` section. This SBAT data is CSV-formatted and describes a list of
the source components that make up the executable. Typically components
are things like the source repo that the executable is derived from, the
parent repo that it was forked from (if applicable), and the SBAT format
itself (so that the format can be changed later if needed).

A component is identified by name and a generation number. The
generation number is a simple version number that may be different from
the component's human-readable version number; it is always a positive
integer that is incremented when older versions of that component need
to be revoked. Each component also has some human-readable data
associated with it, but that data is not used for comparison.

Here's an example of SBAT metadata for a hypothetical executable called
"Pizza":

    sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
    pizza,2,Pizza,pizza,1.2.3,https://example.com/pizza
    pizza.somecorp,1,SomeCorp,pizza,1.2.3,https://example.com/somecorp

This executable contains three components. The first two fields in each
record are the component name and generation. The rest is all
human-readable data that isn't used for comparison. After removing the
human-readable parts we're left with:

    sbat,1
    pizza,2
    pizza.somecorp,1

The first component is always for the SBAT format itself. If at some
point the SBAT format needed to change in a breaking way, all existing
uses of SBAT v1 could be revoked. The second component in this example
is the official repo for the Pizza program. The third component is
SomeCorp's fork of Pizza. This repo might closely follow the upstream
repo but add in a few special features. In the event that SomeCorp makes
a security mistake that only affects their fork, it's important to be
able to revoke pizza.somecorp without having to revoke all pizzas.

Note that even though `pizza.somecorp` refers to a fork of `pizza`, as
far as SBAT is concerned these are distinct components that have no
shared relationship.

## Revocation data

The revocation data is normally stored in an authenticated UEFI
variable. Like the image metadata, it is a CSV-formatted list of
components. Here's an example:

    sbat,1,20210723
    pizza,2
    
As with image metadata, only the first two fields in each record are
used, the rest is treated as a human-readable comment.

Each component record describes a minimum generation (version) for that
component. If an image's component is in the revocation list, that
component's generation must be greater than or equal to the version in
the revocation list. If the image has a component that isn't in the
revocation list at all, that component is implicitly allowed.

So in this example, generation 1 of the `pizza` component has been
revoked. Generation 2 and higher are allowed. The `pizza.somecorp`
component is not in the revocation list at all, so any generation of
that component is allowed. The `sbat` component is in the revocation
list, but since the generation is 1, and 1 is the lowest possible
generation number, all versions of `sbat` are allowed.

Example of image metadata that would be allowed by the example
revocation:

    sbat,1
    pizza,2
    
This would also be allowed:

    sbat,1
    pizza,2,
    pizza.somecorp,1
    
Whereas this would not be allowed due to the `pizza` component:

    sbat,1
    pizza,1,
    pizza.somecorp,2

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option.

## Disclaimer

This project is not an official Google project. It is not supported by
Google and Google specifically disclaims all warranties as to its quality,
merchantability, or fitness for a particular purpose.

[SBAT.md]: https://github.com/rhboot/shim/blob/main/SBAT.md
