//! iprev ptype and it's properties

/// iprev ptypes
#[derive(Clone, Debug, PartialEq)]
pub enum IpRevProperty<'hdr> {
    /// iprev.policy
    Policy(IpRevPolicy<'hdr>),
}

/// iprev ptype policy
#[derive(Clone, Debug, PartialEq)]
pub enum IpRevPolicy<'hdr> {
    /// policy.iprev
    IpRev(&'hdr str),
}
