// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use fs_err as fs;
use object::{Object, ObjectSection};
use std::path::{Path, PathBuf};

/// Tool for working with SBAT (UEFI Secure Boot Advanced Targeting).
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

// TODO:
//
// * Action to add a '.sbat' section to an existing PE file.
//
// * Validate/pretty-print a CSV file.
//
// * Support more than one input file at a time.

#[derive(Subcommand)]
enum Action {
    /// Print the '.sbat' section of a PE executable.
    Dump { input: PathBuf },

    /// Validate and pretty-print the '.sbat' section of a PE executable.
    Validate { input: PathBuf },
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

fn validate_sbat(_input: &Path) -> Result<()> {
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    match &args.action {
        Action::Dump { input } => dump_sbat(input),
        Action::Validate { input } => validate_sbat(input),
    }
}
