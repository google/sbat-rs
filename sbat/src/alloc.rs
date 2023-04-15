use crate::{Component, Entry, ImageSbat, Result, RevocationSbat};
use ascii::AsciiStr;
use rust_alloc::vec::Vec;

/// Image SBAT metadata.
///
/// This contains SBAT entries parsed from the `.sbat` section of a UEFI
/// PE executable.
///
/// See the [crate] documentation for a usage example.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct ImageSbatVec<'a>(Vec<Entry<'a>>);

impl<'a> ImageSbatVec<'a> {
    /// Create a new `ImageSbatVec`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an SBAT entry.
    pub fn push(&mut self, entry: Entry<'a>) {
        self.0.push(entry);
    }
}

impl<'a> ImageSbat<'a> for ImageSbatVec<'a> {
    fn entries(&self) -> &[Entry<'a>] {
        &self.0
    }

    fn try_push(&mut self, entry: Entry<'a>) -> Result<()> {
        self.push(entry);
        Ok(())
    }
}

/// SBAT revocation data.
///
/// This contains SBAT revocation data parsed from a UEFI variable such
/// as `SbatLevel`.
///
/// See the [crate] documentation for a usage example.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevocationSbatVec<'a> {
    date: Option<&'a AsciiStr>,
    components: Vec<Component<'a>>,
}

impl<'a> RevocationSbatVec<'a> {
    /// Create an empty `RevocationSbatVec`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a revoked component.
    fn push(&mut self, component: Component<'a>) {
        self.components.push(component);
    }
}

impl<'a> RevocationSbat<'a> for RevocationSbatVec<'a> {
    fn date(&self) -> Option<&AsciiStr> {
        self.date
    }

    fn set_date(&mut self, date: Option<&'a AsciiStr>) {
        self.date = date;
    }

    fn revoked_components(&self) -> &[Component<'a>] {
        &self.components
    }

    fn try_push(&mut self, component: Component<'a>) -> Result<()> {
        self.push(component);
        Ok(())
    }
}
