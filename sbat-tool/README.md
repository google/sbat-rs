# sbat-tool

[![Crates.io](https://img.shields.io/crates/v/sbat-tool)](https://crates.io/crates/sbat-tool)

This is a tool for working with [SBAT][SBAT.md]. It supports extracting
the `.sbat` section of a PE executable and either printing it directly,
or validating that it parses correctly and pretty-printing it.

Install with:

```console
cargo install sbat-tool
```

## Example

```console
$ sbat-tool validate /boot/efi/boot/bootx64.EFI
+-------------+-----+--------------------+---------+-------------+------------------------------------------------------+
| component   | gen | vendor             | package | version     | url                                                  |
+-------------+-----+--------------------+---------+-------------+------------------------------------------------------+
| sbat        | 1   | SBAT Version       | sbat    | 1           | https://github.com/rhboot/shim/blob/main/SBAT.md     |
+-------------+-----+--------------------+---------+-------------+------------------------------------------------------+
| shim        | 1   | UEFI shim          | shim    | 1           | https://github.com/rhboot/shim                       |
+-------------+-----+--------------------+---------+-------------+------------------------------------------------------+
| shim.redhat | 1   | The Fedora Project | shim    | 15.4-5.fc33 | https://src.fedoraproject.org/rpms/shim-unsigned-x64 |
+-------------+-----+--------------------+---------+-------------+------------------------------------------------------+
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option.

## Disclaimer

This project is not an official Google project. It is not supported by
Google and Google specifically disclaims all warranties as to its quality,
merchantability, or fitness for a particular purpose.

[SBAT.md]: https://github.com/rhboot/shim/blob/main/SBAT.md
