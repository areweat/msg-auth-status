//! Parsed Authetication-Results Header

use crate::auth::{AuthProperty, SmtpAuthResult};
use crate::dkim::{DkimProperty, DkimResult};
use crate::iprev::{IpRevProperty, IpRevResult};
use crate::spf::{SpfProperty, SpfResult};

use crate::error::AuthResultsError;

/// Parsed Authentication-Results
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuthenticationResults<'hdr> {
    /// Relevant host to this record
    pub host: Option<HostVersion<'hdr>>,
    /// Parsed auth = .. records
    pub smtp_auth_result: Vec<SmtpAuthResult<'hdr>>,
    /// Parsed spf = .. records
    pub spf_result: Vec<SpfResult<'hdr>>,
    /// Parsed dkim = .. records
    pub dkim_result: Vec<DkimResult<'hdr>>,
    /// Parsed iprev = .. records
    pub iprev_result: Vec<IpRevResult<'hdr>>,
    /// Whether none was encountered denoting no result
    pub none_done: bool,
    /// Unparsed raw
    pub raw: Option<&'hdr str>,
    /// Parsing error if any
    pub error: Option<AuthResultsError>,
}

/// Host and version relating to the results
#[derive(Clone, Debug, PartialEq)]
pub struct HostVersion<'hdr> {
    /// Host
    pub host: &'hdr str,
    /// Version
    pub version: Option<u32>,
}

/// Auth-Result properties
#[derive(Clone, Debug, PartialEq)]
pub enum Prop<'hdr> {
    /// auth method properties
    Auth(AuthProperty<'hdr>),
    /// dkim method properties
    Dkim(DkimProperty<'hdr>),
    //dmarc method properties
    //Dmarc(DmarcProperty<'hdr>),
    /// iprev method properties
    IpRev(IpRevProperty<'hdr>),
    /// spf method properties
    Spf(SpfProperty<'hdr>),
    /// unknown method properties
    Unknown(UnknownProperty<'hdr>),
}

/// Unknown method properties
#[derive(Clone, Debug, PartialEq)]
pub struct UnknownProperty<'hdr> {
    /// Unknown ptype
    ptype: &'hdr str,
    /// Unknown property key
    pkey: &'hdr str,
    /// Unknown property value
    pval: &'hdr str,
}
