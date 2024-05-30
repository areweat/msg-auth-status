//! auth ptype and it's properties
//!
//! See IANA Assignments
//! https://www.iana.org/assignments/email-auth/email-auth.xhtml
//!
//! And Auth in RFC 8601 s. 2.7

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub enum AuthProperty<'hdr> {
    Smtp(AuthSmtp<'hdr>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum AuthSmtp<'hdr> {
    MailFrom(&'hdr str),
    Auth(&'hdr str),
}

/*
#[derive(Clone, Debug, PartialEq)]
pub enum AuthPtype {
    Smtp,
    SmtpDotAuth,
    Mail,
    MailDotAuth,
}
*/
