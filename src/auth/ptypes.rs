//! auth ptype and it's properties
//!
//! See IANA Assignments
//! https://www.iana.org/assignments/email-auth/email-auth.xhtml
//!
//! And Auth in RFC 8601 s. 2.7

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub enum AuthProperty<'hdr> {
    SmtpAuth(&'hdr str),
    MailFrom(&'hdr str),
}

#[derive(Clone, Debug, PartialEq)]
pub enum AuthPtype {
    Smtp,
    SmtpDotAuth,
    Mail,
    MailDotAuth,
}
