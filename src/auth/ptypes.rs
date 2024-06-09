//! auth ptype and it's properties
//!
//! And Auth in RFC 8601 s. 2.7

/// auth ptypes
#[derive(Clone, Debug, PartialEq)]
pub enum AuthProperty<'hdr> {
    /// smtp.*
    Smtp(AuthSmtp<'hdr>),
}

/// auth smtp.* properties
#[derive(Clone, Debug, PartialEq)]
pub enum AuthSmtp<'hdr> {
    /// smtp.mailfrom
    MailFrom(&'hdr str),
    /// smtp.auth
    Auth(&'hdr str),
}
