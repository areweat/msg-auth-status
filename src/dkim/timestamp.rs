#[derive(Clone, Debug, Default, PartialEq)]
pub enum DkimTimestamp<'hdr> {
    #[default]
    Unknown,
    Raw(&'hdr str),
}

#[derive(Debug, PartialEq)]
pub enum DkimTimestampError {}

impl<'hdr> TryFrom<&'hdr str> for DkimTimestamp<'hdr> {
    type Error = DkimTimestampError;

    fn try_from(in_str: &'hdr str) -> Result<Self, Self::Error> {
        Ok(Self::Raw(in_str))
    }
}
