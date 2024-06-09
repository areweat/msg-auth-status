//! DKIM Property types or 'ptype' per RFC 8601 s. 2.7.1
//!
//! IANA Maintains the registry for all the possible Parameters
//!
//! DKIM-Signature Tag Specifications are defined in RFC 6376 s. 7.2
//!
//! Also see s. 7.10 for the DKIM-Signature field

use super::*;

/// DKIM ptypes
#[derive(Clone, Debug, PartialEq)]
pub enum DkimProperty<'hdr> {
    /// header.* subset of RFC 6376 tags
    Header(DkimHeader<'hdr>),
    /// policy.*
    Policy(DkimPolicy<'hdr>),
}

/// DKIM policy ptype properties
#[derive(Clone, Debug, PartialEq)]
pub enum DkimPolicy<'hdr> {
    /// Unknown
    Unknown(&'hdr str, &'hdr str),
}
