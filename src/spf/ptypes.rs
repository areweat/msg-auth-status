//! SPF ptype and it's properties
//!
//! See IANA Assignments
//! https://www.iana.org/assignments/email-auth/email-auth.xhtml
//!
//! And SPF in RFC 8601 s. 2.7.2

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub enum SpfProperty<'hdr> {
    Smtp(SpfSmtp<'hdr>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum SpfSmtp<'hdr> {
    MailFrom(&'hdr str),
    Helo(&'hdr str),
}

#[derive(Clone, Debug, PartialEq)]
pub enum SpfPtype {
    Smtp,
    SmtpMailFrom,
    SmtpHelo,
}
