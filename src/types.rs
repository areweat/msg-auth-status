//! Re-export in under root

use crate::auth::{AuthProperty, SmtpAuthResult};
use crate::dkim::{DkimProperty, DkimResult};
use crate::iprev::{IpRevProperty, IpRevResult};
use crate::spf::{SpfProperty, SpfResult};

#[derive(Debug, Default)]
pub struct AuthenticationResults<'hdr> {
    pub a: Option<&'hdr str>,
    pub host: Option<&'hdr str>,
    pub smtp_auth_result: Vec<SmtpAuthResult<'hdr>>,
    pub spf_result: Vec<SpfResult<'hdr>>,
    pub dkim_result: Vec<DkimResult<'hdr>>,
    pub iprev_result: Vec<IpRevResult<'hdr>>,
    pub none_done: bool,
}

#[derive(Debug)]
pub struct HostVersion<'hdr> {
    pub host: &'hdr str,
    pub version: Option<u32>,
}

#[derive(Debug)]
pub enum Prop<'hdr> {
    Auth(AuthProperty<'hdr>),
    Dkim(DkimProperty<'hdr>),
    //Dmarc(DmarcProperty<'hdr>),
    IpRev(IpRevProperty<'hdr>),
    Spf(SpfProperty<'hdr>),
    Unknown(UnknownProperty<'hdr>),
}

#[derive(Debug)]
pub struct UnknownProperty<'hdr> {
    ptype: &'hdr str,
    pval: &'hdr str,
}
