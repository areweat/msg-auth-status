#[derive(Clone, Debug, Default, PartialEq)]
pub enum DkimCanonicalization<'hdr> {
    #[default]
    /// simple/simple & simple algorithm tolerates almost no modification
    Simple,
    /// relaxed/simple & relaxed algorithm tolerates common modifications such
    /// as whitespace replacement and header field line rewrapping.
    Relaxed,
    /// Unknown RFC does not define
    Unknown(&'hdr str),
}

#[derive(Clone, Debug, PartialEq)]
pub enum DkimCanonicalizationError {}

impl<'hdr> TryFrom<&'hdr str> for DkimCanonicalization<'hdr> {
    type Error = DkimCanonicalizationError;

    fn try_from(hdr: &'hdr str) -> Result<Self, Self::Error> {
        let ret = match hdr {
            "simple" => Self::Simple,
            "simple/simple" => Self::Simple,
            "relaxed" => Self::Relaxed,
            "relaxed/simple" => Self::Relaxed,
            _ => Self::Unknown(hdr),
        };
        Ok(ret)
    }
}
