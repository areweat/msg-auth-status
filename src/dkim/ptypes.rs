//! DKIM Property types or 'ptype' per RFC 8601 s. 2.7.1
//!
//! IANA Maintains the registry for all the possible Parameters
//! https://www.iana.org/assignments/dkim-parameters/dkim-parameters.xhtml
//!
//! DKIM-Signature Tag Specifications are defined in RFC 6376 s. 7.2
//!
//! Also see s. 7.10 for the DKIM-Signature field

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub enum DkimProperty<'hdr> {
    Header(DkimHeader<'hdr>),
    Policy(DkimPolicy<'hdr>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum DkimPolicy<'hdr> {
    /// Unknown
    Unknown(&'hdr str, &'hdr str),
}
