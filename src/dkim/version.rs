//! DKIM Version

/// DKIM Version
#[derive(Clone, Debug, PartialEq)]
pub enum DkimVersion<'hdr> {
    /// RFC just says this should be used
    One,
    /// Something else outside RFC
    Unknown(&'hdr str),
}

use crate::error::DkimVersionError;

impl<'hdr> TryFrom<&'hdr str> for DkimVersion<'hdr> {
    type Error = DkimVersionError;

    fn try_from(in_str: &'hdr str) -> Result<Self, Self::Error> {
        let ret = match in_str {
            "1" => Self::One,
            _ => Self::Unknown(in_str),
        };
        Ok(ret)
    }
}
