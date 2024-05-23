//! Re-export in under root

use crate::auth::{AuthProperty, SmtpAuthResult};
use crate::dkim::{DkimProperty, DkimResult};
use crate::iprev::{IpRevProperty, IpRevResult};
use crate::spf::{SpfProperty, SpfResult};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuthenticationResults<'hdr> {
    pub host: Option<HostVersion<'hdr>>,
    pub smtp_auth_result: Vec<SmtpAuthResult<'hdr>>,
    pub spf_result: Vec<SpfResult<'hdr>>,
    pub dkim_result: Vec<DkimResult<'hdr>>,
    pub iprev_result: Vec<IpRevResult<'hdr>>,
    pub none_done: bool,
    pub raw: Option<&'hdr str>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HostVersion<'hdr> {
    pub host: &'hdr str,
    pub version: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Prop<'hdr> {
    Auth(AuthProperty<'hdr>),
    Dkim(DkimProperty<'hdr>),
    //Dmarc(DmarcProperty<'hdr>),
    IpRev(IpRevProperty<'hdr>),
    Spf(SpfProperty<'hdr>),
    Unknown(UnknownProperty<'hdr>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct UnknownProperty<'hdr> {
    ptype: &'hdr str,
    pval: &'hdr str,
}
