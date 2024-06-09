//! DKIM Timestamp

/// DKIM Timestamp
#[derive(Clone, Debug, Default, PartialEq)]
pub enum DkimTimestamp<'hdr> {
    /// Unknown timestamp
    #[default]
    Unknown,
    /// Raw value - parsing delegated downstream
    Raw(&'hdr str),
}

/// Currently infallible, may change in the future
#[derive(Debug, PartialEq)]
pub enum DkimTimestampError {}

impl<'hdr> TryFrom<&'hdr str> for DkimTimestamp<'hdr> {
    type Error = DkimTimestampError;

    fn try_from(in_str: &'hdr str) -> Result<Self, Self::Error> {
        Ok(Self::Raw(in_str))
    }
}
