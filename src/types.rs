//! All public types
//! Re-export in under root

pub mod auth;
pub mod dkim;
pub mod iprev;
pub mod spf;

use crate::auth::SmtpAuthResult;
use crate::dkim::DkimResult;
use crate::iprev::IpRevResult;
use crate::spf::SpfResult;

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
