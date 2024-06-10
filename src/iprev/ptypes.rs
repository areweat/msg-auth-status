//! iprev ptype and it's properties

/// iprev ptypes
#[derive(Clone, Debug, PartialEq)]
pub enum IpRevProperty<'hdr> {
    /// iprev.policy
    Policy(IpRevPolicy<'hdr>),
    /// smtp.* rfc-undefined
    Smtp(IpRevSmtp<'hdr>),
}

/// iprev ptype policy
#[derive(Clone, Debug, PartialEq)]
pub enum IpRevPolicy<'hdr> {
    /// policy.iprev
    IpRev(&'hdr str),
    /// policy.*
    Unknown(&'hdr str, &'hdr str),
}

/// iprev ptype smtp (fastmail breaks RFC)
#[derive(Clone, Debug, PartialEq)]
pub enum IpRevSmtp<'hdr> {
    /// smtp.*
    Unknown(&'hdr str, &'hdr str),
}
