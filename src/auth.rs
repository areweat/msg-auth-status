#[derive(Clone, Debug, Default, PartialEq)]
pub struct SmtpAuthResult<'hdr> {
    pub code: SmtpAuthResultCode,
    pub smtp_auth: Option<&'hdr str>,
    pub smtp_mailfrom: Option<&'hdr str>,
    pub raw: Option<&'hdr str>,
}

impl<'hdr> SmtpAuthResult<'hdr> {
    pub(crate) fn set_smtp(&mut self, prop: &ptypes::AuthSmtp<'hdr>) -> bool {
        match prop {
            ptypes::AuthSmtp::MailFrom(val) => self.smtp_mailfrom = Some(val),
            ptypes::AuthSmtp::Auth(val) => self.smtp_auth = Some(val),
            _ => {}
        }
        true
    }
}

/// SMTP AUTH Result Codes - s.2.7.4
/// This SMTP Authentication (not DKIM)
//#[derive(Debug, Default, EnumString, StrumDisplay)]
//#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
#[derive(Clone, Debug, Default, PartialEq)]
pub enum SmtpAuthResultCode {
    #[default]
    Unknown,
    /// SMTP authentication was not attempted.
    NoneSmtp,
    /// The SMTP client authenticated to the server
    Pass,
    /// The SMTP client attempted to authenticate but was not successful
    Fail,
    /// The SMTP client attempted to authenticate but was not able to complete
    /// the attempt due to some error that is likely transient in nature
    TempError,
    /// The SMTP client attempted to authenticate but was not able to complete
    /// the attempt due to some error that is likely not transient in nature
    PermError,
}

pub mod ptypes;
pub use ptypes::AuthProperty;
