//! iprev ptype and it's properties
//!
//! See IANA Assignments
//! https://www.iana.org/assignments/email-auth/email-auth.xhtml
//!
//! And iprev in RFC 8601 s. 2.7

#[derive(Debug)]
pub enum IpRevProperty<'hdr> {
    PolicyIpRev(&'hdr str),
}

#[derive(Debug)]
pub enum IpRevPtype {
    Policy,
    PolicyDotIpRev,
}
