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
    /// Print the '.sbat' section of a PE executable.
    Dump { input: PathBuf },

    /// Validate and pretty-print the '.sbat' section of a PE executable.
    Validate { input: Vec<PathBuf> },
}

fn read_sbat_section(input: &Path) -> Result<Vec<u8>> {
    let data = fs::read(input)?;
    let file = object::File::parse(&*data)?;
    let section = file
        .section_by_name(".sbat")
        .ok_or(anyhow!("missing '.sbat' section"))?;
    Ok(section.data()?.to_vec())
}

fn dump_sbat(input: &Path) -> Result<()> {
    let data = read_sbat_section(input)?;
    let sbat = std::str::from_utf8(&data)?;

    println!("{sbat}");

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
    let mut first = true;
    for input in inputs {
        if first {
            first = false;
        } else {
            println!();
        }
        println!("{}:", input.display());

        let data = read_sbat_section(input)?;
        // TODO: add std error support.
        let image_sbat = ImageSbatVec::parse(&data).unwrap();

        println!("{}", image_sbat_to_table_string(&image_sbat));
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    match &args.action {
        Action::Dump { input } => dump_sbat(input),
        Action::Validate { input } => validate_sbat(input),
    }
}
