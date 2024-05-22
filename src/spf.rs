//! SPF Types

#[derive(Debug, Default)]
pub struct SpfResult<'hdr> {
    pub code: SpfResultCode,
    pub reason: Option<&'hdr str>,
    pub smtp_mailfrom: Option<&'hdr str>,
    pub smtp_helo: Option<&'hdr str>,
}

/// SPF Result Codes - s.2.7.2
/// SPF defined in RFC 7208 s.2.6 - Results evaluation
//#[derive(Debug, Default, EnumString, StrumDisplay)]
//#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
#[derive(Debug, Default)]
pub enum SpfResultCode {
    #[default]
    Unknown,
    /// Either (a) syntactically valid DNS domain name was extracted from the
    /// SMTP session that could be used as the one to be authorized, or (b) no
    /// SPF records were retrieved from the DNS.
    NoneSpf,
    /// An explicit statement that the client is authorized to inject mail with
    /// the given identity.
    Pass,
    /// An explicit statement that the client is not authorized to use the domain
    /// in the given identity.
    Fail,
    /// A weak statement by the publishing ADMD that the host is probably not
    /// authorized.  It has not published a stronger, more definitive policy that
    /// results in a "fail".
    SoftFail,
    /// RFC 8601 - Section 2.4
    /// Indication that some local policy mechanism was applied that augments or
    /// even replaces (i.e., overrides) the result returned by the authentication
    /// mechanism.  The property and value in this case identify the local policy
    /// that was applied and the result it returned.
    Policy,
    /// The ADMD has explicitly stated that it is not asserting whether the IP
    /// address is authorized.
    Neutral,
    /// The SPF verifier encountered a transient (generally DNS) error while
    /// performing the check.  A later retry may succeed without further DNS
    /// operator action.
    TempError,
    /// The domain's published records could not be correctly interpreted.
    /// This signals an error condition that definitely requires DNS operator
    /// intervention to be resolved.
    PermError,
}

pub mod ptypes;
pub use ptypes::SpfProperty;
