//! DKIM header.* or header tags per RFC 6376

use super::*;

/// See RFC 6376 s. 3.5 for the full definitions
#[derive(Clone, Debug, PartialEq)]
pub enum DkimHeader<'hdr> {
    /// Required - Version
    V(DkimVersion<'hdr>),
    /// Signature Algorithm - see s. 3.3 & IANA
    A(DkimAlgorithm<'hdr>),
    /// Signature data in base64 (note about FWS in s. 3.5 b=)
    B(&'hdr str),
    /// Hash of canonicalized body part of the message as limited by the 'l=' Body length limit tag - base64.
    /// Note: Whitespaces / WHS are ignored
    Bh(&'hdr str),
    /// Required -  Message canonicalization informs the verifier of the type of canonicalization used to prepare the message for signing. See s.3.4
    C(DkimCanonicalization<'hdr>),
    /// Required - The SDID claiming responsibility for an introduction of a message into the mail stream.
    /// The SDID MUST correspond to a valid DNS name under which the DKIM key ecord is published.
    D(&'hdr str),
    /// Required - Signed header fields separated by colon ':' - see 'h='
    H(&'hdr str),
    /// Optional - The Agent or User Identifier (AUID) on behalf of which the SDID is taking responsibility.
    I(&'hdr str),
    /// Optional - Body length limit - see misuse on RFC 6376 s. 8.2.
    L(&'hdr str),
    /// Optional - Query method - currently only Dns.
    Q(&'hdr str),
    /// Required - The selector subdividing the namespace for the "d=" (domain) tag.
    /// Internationalized selector names MUST be encoded as A-labels, as described in Section 2.3 of RFC 5890.
    S(&'hdr str),
    /// Recommended - Signature Timestamp
    T(DkimTimestamp<'hdr>),
    /// Recommended - Signature Expiration
    X(DkimTimestamp<'hdr>),
    /// Optional - Copied header fields
    Z(&'hdr str),
    /// RFC 6541
    Atps(&'hdr str),
    /// RFC 6541
    Atpsh(&'hdr str),
    /// RFC 6651
    R(&'hdr str),
    /// RFC 5322
    Rfc5322From(&'hdr str),
    /// Unknown
    Unknown(&'hdr str, &'hdr str),
}

/// Currently no errors - may change in the future
#[derive(Clone, Debug, PartialEq)]
pub enum DkimHeaderError {}
