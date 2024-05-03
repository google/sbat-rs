# sbat-rs

[![Coverage Status](https://coveralls.io/repos/github/google/sbat-rs/badge.svg?branch=main)](https://coveralls.io/github/google/sbat-rs?branch=main)

This repo contains tools for working with [SBAT][SBAT.md]. There are two
Rust packages:
* [`sbat`] - A no-std library for parsing SBAT and doing revocation checks.
  * [![Crates.io](https://img.shields.io/crates/v/sbat)](https://crates.io/crates/sbat) [![Docs.rs](https://docs.rs/sbat/badge.svg)](https://docs.rs/sbat)
* [`sbat-tool`] - A command-line utility for working with SBAT.
  * [![Crates.io](https://img.shields.io/crates/v/sbat-tool)](https://crates.io/crates/sbat-tool)

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option.

## Disclaimer

This project is not an official Google project. It is not supported by
Google and Google specifically disclaims all warranties as to its quality,
merchantability, or fitness for a particular purpose.

[SBAT.md]: https://github.com/rhboot/shim/blob/main/SBAT.md
[`sbat`]: ./sbat
[`sbat-tool`]: ./sbat-tool
