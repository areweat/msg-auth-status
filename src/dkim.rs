//! Public DKIM types exported by this library

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DkimResult<'hdr> {
    pub code: DkimResultCode,
    pub reason: Option<&'hdr str>,
    pub header_d: Option<&'hdr str>,
    pub header_i: Option<&'hdr str>,
    pub header_b: Option<&'hdr str>,
    pub header_a: Option<DkimAlgorithm<'hdr>>,
    pub header_s: Option<&'hdr str>,
    pub raw: Option<&'hdr str>,
}

impl<'hdr> DkimResult<'hdr> {
    pub(crate) fn set_header(&mut self, prop: &ptypes::DkimHeader<'hdr>) -> bool {
        match prop {
            ptypes::DkimHeader::D(val) => self.header_d = Some(val),
            ptypes::DkimHeader::I(val) => self.header_i = Some(val),
            ptypes::DkimHeader::B(val) => self.header_b = Some(val),
            ptypes::DkimHeader::A(val) => self.header_a = Some(val.clone()),
            ptypes::DkimHeader::S(val) => self.header_s = Some(val),
            _ => {}
        }
        true
    }
}

/// DKIM Result Codes - s.2.7.1
//#[derive(Debug, Default, EnumString, StrumDisplay)]
//#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
#[derive(Clone, Debug, Default, PartialEq)]
pub enum DkimResultCode {
    #[default]
    Unknown,
    /// The message was not signed.
    NoneDkim,
    /// The message was signed, the signature or signatures were
    /// acceptable to the ADMD, and the signature(s) passed verification
    /// tests.
    Pass,
    /// The message was signed and the signature or signatures were acceptable
    /// to the ADMD, but they failed the verification test(s).
    Fail,
    /// The message was signed, but some aspect of the signature or
    /// signatures was not acceptable to the ADMD.
    Policy,
    /// The message was signed, but the signature or signatures
    /// contained syntax errors or were not otherwise able to be
    /// processed.  This result is also used for other failures not
    /// covered elsewhere in this list.
    Neutral,
    /// The message could not be verified due to some error that
    /// is likely transient in nature, such as a temporary inability to
    /// retrieve a public key.  A later attempt may produce a final
    /// result.
    TempError,
    /// The message could not be verified due to some error that
    /// is unrecoverable, such as a required header field being absent.
    /// A later attempt is unlikely to produce a final result.
    PermError,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum DKimCanonicalization<'hdr> {
    #[default]
    /// simple/simple & simple algorithm tolerates almost no modification
    Simple,
    /// relaxed/simple & relaxed algorithm tolerates common modifications such
    /// as whitespace replacement and header field line rewrapping.    
    Relaxed,
    /// Unknown RFC does not define
    Unknown(&'hdr str),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum DkimTimestamp<'hdr> {
    #[default]
    Unknown,
    Raw(&'hdr str),
}

#[derive(Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum DkimAlgorithm<'hdr> {
    /// Do not use
    Rsa_Sha1,
    /// Widely supported
    Rsa_Sha256,
    /// Please support this - not widely supported yet
    Ed25519_Sha256,
    Unknown(&'hdr str),
}
#[derive(Clone, Debug, PartialEq)]
pub enum DkimVersion<'hdr> {
    /// RFC just says this should be used
    One,
    /// Something else outside RFC
    Unknown(&'hdr str),
}

pub mod ptypes;
pub use ptypes::DkimProperty;
