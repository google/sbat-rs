// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use fs_err as fs;
use object::{Object, ObjectSection};
use std::path::PathBuf;

/// Tool for working with SBAT (UEFI Secure Boot Advanced Targeting).
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Print the '.sbat' section of a PE executable.
    Dump { input: PathBuf },
    // TODO(nicholasbishop): add more options, such as validating PE
    // data and adding a '.sbat' section to an existing executable.
}

fn dump_sbat(input: PathBuf) -> Result<()> {
    let data = fs::read(input)?;
    let file = object::File::parse(&*data)?;
    if let Some(section) = file.section_by_name(".sbat") {
        let section_data = section.data()?;
        let sbat = std::str::from_utf8(section_data)?;

        println!("{sbat}");

        Ok(())
    } else {
        bail!("missing '.sbat' section");
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.action {
        Action::Dump { input } => dump_sbat(input),
    }
}
