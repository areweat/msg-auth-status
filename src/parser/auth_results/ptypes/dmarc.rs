//! dmarc ptype and it's properties
//!
//! See IANA Assignments
//! https://www.iana.org/assignments/email-auth/email-auth.xhtml
//!
//! And Auth in RFC 8601 s. 2.7

#[derive(Debug)]
pub enum DmarcProperty<'hdr> {
    /// RFC 7489
    HeaderFrom(&'hdr str),
    /// RFC 7489
    PolicyDmarc(&'hdr str),
}

#[derive(Debug)]
pub enum DmarcPtype {
    Header,
    HeaderDotFrom,
    Policy,
    PolicyDotDmarc,
}
