//! Method dkim Result and associated types

/// Parsed dkim Result - see RFC 6376 for the header tags
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DkimResult<'hdr> {
    /// dkim Result (per RFC)
    pub code: DkimResultCode,
    /// Reason if supplied (per RFC)
    pub reason: Option<&'hdr str>,
    /// header.d (per RFC)
    pub header_d: Option<&'hdr str>,
    /// header.i (per RFC)
    pub header_i: Option<&'hdr str>,
    /// header_b (per RFC)
    pub header_b: Option<&'hdr str>,
    /// header.a (per RFC)
    pub header_a: Option<DkimAlgorithm<'hdr>>,
    /// header.s (per RFC)
    pub header_s: Option<&'hdr str>,
    /// Unparsed raw
    pub raw: Option<&'hdr str>,
}

impl<'hdr> DkimResult<'hdr> {
    pub(crate) fn set_header(&mut self, prop: &DkimHeader<'hdr>) -> bool {
        match prop {
            DkimHeader::D(val) => self.header_d = Some(val),
            DkimHeader::I(val) => self.header_i = Some(val),
            DkimHeader::B(val) => self.header_b = Some(val),
            DkimHeader::A(val) => self.header_a = Some(val.clone()),
            DkimHeader::S(val) => self.header_s = Some(val),
            _ => {}
        }
        true
    }
    // TODO: Not supported
    pub(crate) fn set_policy(&mut self, _prop: &ptypes::DkimPolicy<'hdr>) -> bool {
        true
    }
}

/// DKIM Result Codes - s.2.7.1
#[derive(Clone, Debug, Default, PartialEq)]
pub enum DkimResultCode {
    /// Result code not seen
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

/// The 'q' Tag - see RFC 6376 s. 3.5
#[derive(Clone, Debug, Default, PartialEq)]
pub enum DkimQueryMethod<'hdr> {
    /// Domain Name System (DNS)
    #[default]
    DnsTxt,
    /// Unknown
    Unknown(&'hdr str),
}

pub mod ptypes;
pub use ptypes::DkimProperty;

mod algorithm;
pub use algorithm::DkimAlgorithm;

mod canonicalization;
pub use canonicalization::DkimCanonicalization;

mod signature;
pub use signature::DkimSignature;

mod header;
pub use header::DkimHeader;

mod timestamp;
pub use timestamp::DkimTimestamp;

mod version;
pub use version::DkimVersion;
