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
use itertools::Itertools;
use object::{Object, ObjectSection};
use sbat::{
    ImageSbat, RevocationSbat, RevocationSection, REVOCATION_SECTION_NAME,
    SBAT_SECTION_NAME,
};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

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
        #[arg(long, default_value = SBAT_SECTION_NAME)]
        section: String,
        input: PathBuf,
    },

    /// Validate and pretty-print the '.sbat' section of a PE executable.
    Validate { input: Vec<PathBuf> },

    /// Validate and pretty-print the '.sbatlevel' section of a PE executable.
    ValidateRevocations { input: Vec<PathBuf> },
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

fn image_sbat_to_table_string(image_sbat: &ImageSbat) -> String {
    let mut builder = tabled::builder::Builder::default();
    builder.push_record([
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

fn sbat_level_section_to_table_string(
    previous: &RevocationSbat,
    latest: &RevocationSbat,
) -> String {
    let mut builder = tabled::builder::Builder::default();
    builder.push_record([
        "previous name",
        "previous gen",
        "latest name",
        "latest gen",
    ]);
    for row in previous
        .revoked_components()
        .zip_longest(latest.revoked_components())
    {
        let mut record = vec![];
        for comp in [row.clone().left(), row.right()] {
            if let Some(comp) = comp {
                record.push(comp.name.to_string());
                record.push(comp.generation.to_string());
            } else {
                record.extend(["".to_string(), "".to_string()]);
            }
        }

        builder.push_record(record);
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

        let data = read_pe_section(input, SBAT_SECTION_NAME)?;
        let image_sbat = ImageSbat::parse(&data)?;

        let table = image_sbat_to_table_string(image_sbat);
        ignore_broken_pipe(writeln!(stdout, "{table}"))?;
    }

    Ok(())
}

fn validate_revocations(inputs: &Vec<PathBuf>) -> Result<()> {
    let mut stdout = io::stdout();

    let mut first = true;
    for input in inputs {
        if first {
            first = false;
        } else {
            ignore_broken_pipe(writeln!(stdout))?;
        }
        ignore_broken_pipe(writeln!(stdout, "{}:", input.display()))?;

        let data = read_pe_section(input, REVOCATION_SECTION_NAME)?;

        let sbat_level_section = RevocationSection::parse(&data)?;
        let previous = RevocationSbat::parse(sbat_level_section.previous())?;
        let latest = RevocationSbat::parse(sbat_level_section.latest())?;

        let table = sbat_level_section_to_table_string(previous, latest);
        ignore_broken_pipe(writeln!(stdout, "{table}"))?;
    }

    Ok(())
}

fn run_action(args: &Args) -> Result<()> {
    match &args.action {
        Action::Dump { input, section } => dump_section(input, section),
        Action::Validate { input } => validate_sbat(input),
        Action::ValidateRevocations { input } => validate_revocations(input),
    }
}

fn main() -> Result<()> {
    run_action(&Args::parse())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_sbat_to_table_string() {
        let image_sbat = ImageSbat::parse(
            b"pizza,2,SomeCorp,pizza,1.2.3,https://example.com/somecorp",
        )
        .unwrap();
        let expected =
            "
+-----------+-----+----------+---------+---------+------------------------------+
| component | gen | vendor   | package | version | url                          |
+-----------+-----+----------+---------+---------+------------------------------+
| pizza     | 2   | SomeCorp | pizza   | 1.2.3   | https://example.com/somecorp |
+-----------+-----+----------+---------+---------+------------------------------+";
        assert_eq!(image_sbat_to_table_string(&image_sbat), expected.trim());
    }

    #[test]
    fn test_sbat_level_section_to_table_string() {
        let previous = RevocationSbat::parse(b"sbat,1").unwrap();
        let latest = RevocationSbat::parse(b"sbat,1\nshim,2").unwrap();
        let expected = "
+---------------+--------------+-------------+------------+
| previous name | previous gen | latest name | latest gen |
+---------------+--------------+-------------+------------+
| sbat          | 1            | sbat        | 1          |
+---------------+--------------+-------------+------------+
|               |              | shim        | 2          |
+---------------+--------------+-------------+------------+";
        assert_eq!(
            sbat_level_section_to_table_string(previous, latest),
            expected.trim()
        );
    }

    /// Test that a bad input path doesn't cause a panic.
    #[test]
    fn test_invalid_path() {
        assert!(run_action(&Args {
            action: Action::Dump {
                section: SBAT_SECTION_NAME.into(),
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

        assert!(run_action(&Args {
            action: Action::ValidateRevocations {
                input: vec!["/bad/path".into()],
            }
        })
        .is_err());
    }
}
