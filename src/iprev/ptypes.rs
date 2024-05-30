//! iprev ptype and it's properties
//!
//! See IANA Assignments
//! https://www.iana.org/assignments/email-auth/email-auth.xhtml
//!
//! And iprev in RFC 8601 s. 2.7

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub enum IpRevProperty<'hdr> {
    Policy(IpRevPolicy<'hdr>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum IpRevPolicy<'hdr> {
    IpRev(&'hdr str),
}
