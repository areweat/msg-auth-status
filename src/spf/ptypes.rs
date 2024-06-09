//! SPF ptype and it's properties

/// SPF ptypes
#[derive(Clone, Debug, PartialEq)]
pub enum SpfProperty<'hdr> {
    /// smtp.*
    Smtp(SpfSmtp<'hdr>),
}

/// SPF ptype smtp property keys
#[derive(Clone, Debug, PartialEq)]
pub enum SpfSmtp<'hdr> {
    /// smtp.mailfrom
    MailFrom(&'hdr str),
    /// smtp.helo
    Helo(&'hdr str),
}
