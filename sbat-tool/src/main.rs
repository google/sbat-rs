// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use anyhow::{anyhow, Result};
use ascii::AsciiStr;
use clap::{Parser, Subcommand};
use fs_err as fs;
use object::{Object, ObjectSection};
use sbat::{ImageSbat, ImageSbatVec};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const SBAT_SECTION: &str = ".sbat";

/// Tool for working with SBAT (UEFI Secure Boot Advanced Targeting).
#[derive(Parser)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

// TODO:
//
// * Action to add a '.sbat' section to an existing PE file.
//
// * Validate/pretty-print a CSV file.

#[derive(Subcommand)]
enum Action {
    /// Print a section of a PE executable.
    Dump {
        /// Name of the section to print.
        #[arg(long, default_value = ".sbat")]
        section: String,
        input: PathBuf,
    },

    /// Validate and pretty-print the '.sbat' section of a PE executable.
    Validate { input: Vec<PathBuf> },
}

fn read_pe_section(input: &Path, section_name: &str) -> Result<Vec<u8>> {
    let data = fs::read(input)?;
    let file = object::File::parse(&*data)?;
    let section = file
        .section_by_name(section_name)
        .ok_or(anyhow!("missing '{}' section", section_name))?;
    Ok(section.data()?.to_vec())
}

fn ignore_broken_pipe(result: io::Result<()>) -> io::Result<()> {
    if let Err(err) = result {
        if err.kind() != io::ErrorKind::BrokenPipe {
            return Err(err);
        }
    }

    Ok(())
}

fn dump_section(input: &Path, section_name: &str) -> Result<()> {
    let data = read_pe_section(input, section_name)?;

    ignore_broken_pipe(io::stdout().write_all(&data))?;

    Ok(())
}

fn image_sbat_to_table_string(image_sbat: &ImageSbatVec) -> String {
    let mut builder = tabled::builder::Builder::default();
    builder.set_header([
        "component",
        "gen",
        "vendor",
        "package",
        "version",
        "url",
    ]);
    for entry in image_sbat.entries() {
        let component = entry.component;
        let vendor = entry.vendor;
        let opt_ascii_to_string = |opt: Option<&AsciiStr>| {
            opt.map(|s| s.to_string()).unwrap_or_default()
        };
        builder.push_record([
            component.name.to_string(),
            component.generation.to_string(),
            opt_ascii_to_string(vendor.name),
            opt_ascii_to_string(vendor.package_name),
            opt_ascii_to_string(vendor.version),
            opt_ascii_to_string(vendor.url),
        ]);
    }

    builder.build().to_string()
}

fn validate_sbat(inputs: &Vec<PathBuf>) -> Result<()> {
    let mut stdout = io::stdout();

    let mut first = true;
    for input in inputs {
        if first {
            first = false;
        } else {
            ignore_broken_pipe(writeln!(stdout))?;
        }
        ignore_broken_pipe(writeln!(stdout, "{}:", input.display()))?;

        let data = read_pe_section(input, SBAT_SECTION)?;
        let image_sbat = ImageSbatVec::parse(&data)?;

        let table = image_sbat_to_table_string(&image_sbat);
        ignore_broken_pipe(writeln!(stdout, "{table}"))?;
    }

    Ok(())
}

fn run_action(args: &Args) -> Result<()> {
    match &args.action {
        Action::Dump { input, section } => dump_section(input, section),
        Action::Validate { input } => validate_sbat(input),
    }
}

fn main() -> Result<()> {
    run_action(&Args::parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbat::{Component, Entry, Generation, Vendor};

    fn ascii(s: &str) -> &AsciiStr {
        AsciiStr::from_ascii(s).unwrap()
    }

    #[test]
    fn test_image_sbat_to_table_string() {
        let mut image_sbat = ImageSbatVec::new();
        image_sbat.push(Entry::new(
            Component::new(ascii("pizza"), Generation::new(2).unwrap()),
            Vendor {
                name: Some(ascii("SomeCorp")),
                package_name: Some(ascii("pizza")),
                version: Some(ascii("1.2.3")),
                url: Some(ascii("https://example.com/somecorp")),
            },
        ));
        let expected =
            "
+-----------+-----+----------+---------+---------+------------------------------+
| component | gen | vendor   | package | version | url                          |
+-----------+-----+----------+---------+---------+------------------------------+
| pizza     | 2   | SomeCorp | pizza   | 1.2.3   | https://example.com/somecorp |
+-----------+-----+----------+---------+---------+------------------------------+";
        assert_eq!(image_sbat_to_table_string(&image_sbat), expected.trim());
    }

    /// Test that a bad input path doesn't cause a panic.
    #[test]
    fn test_invalid_path() {
        assert!(run_action(&Args {
            action: Action::Dump {
                section: SBAT_SECTION.into(),
                input: "/bad/path".into(),
            }
        })
        .is_err());

        assert!(run_action(&Args {
            action: Action::Validate {
                input: vec!["/bad/path".into()],
            }
        })
        .is_err());
    }
}
