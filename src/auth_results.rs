//! Parsed Authetication-Results

use crate::auth::AuthProperty;
use crate::dkim::DkimProperty;
use crate::iprev::IpRevProperty;
use crate::spf::SpfProperty;

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
