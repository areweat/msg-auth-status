#[derive(Clone, Debug, Default, PartialEq)]
pub struct IpRevResult<'hdr> {
    pub code: IpRevResultCode,
    pub reason: Option<&'hdr str>,
    pub policy_iprev: Option<&'hdr str>,
    pub raw: Option<&'hdr str>,
}

impl<'hdr> IpRevResult<'hdr> {
    pub(crate) fn set_policy(&mut self, prop: &ptypes::IpRevPolicy<'hdr>) -> bool {
        match prop {
            ptypes::IpRevPolicy::IpRev(val) => self.policy_iprev = Some(val),
            _ => {}
        }
        true
    }
}

/// IpRev Result Codes - s.2.7.3
//#[derive(Debug, Default, EnumString, StrumDisplay)]
//#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
#[derive(Clone, Debug, Default, PartialEq)]
pub enum IpRevResultCode {
    #[default]
    Unknown,
    /// The DNS evaluation succeeded, i.e., the "reverse" and
    /// "forward" lookup results were returned and were in agreement.
    Pass,
    /// The DNS evaluation failed.  In particular, the "reverse" and
    /// "forward" lookups each produced results, but they were not in
    /// agreement, or the "forward" query completed but produced no
    /// result, e.g., a DNS RCODE of 3, commonly known as NXDOMAIN, or an
    /// RCODE of 0 (NOERROR) in a reply containing no answers, was
    /// returned.
    Fail,
    /// The DNS evaluation could not be completed due to some
    /// error that is likely transient in nature, such as a temporary DNS
    /// error, e.g., a DNS RCODE of 2, commonly known as SERVFAIL, or
    /// other error condition resulted.  A later attempt may produce a
    /// final result.
    TempError,
    /// The DNS evaluation could not be completed because no PTR
    /// data are published for the connecting IP address, e.g., a DNS
    /// RCODE of 3, commonly known as NXDOMAIN, or an RCODE of 0 (NOERROR)
    /// in a reply containing no answers, was returned.  This prevented
    /// completion of the evaluation.  A later attempt is unlikely to
    /// produce a final result.
    PermError,
}

pub mod ptypes;
pub use ptypes::IpRevProperty;
