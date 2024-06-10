//! DKIM Signatures

use crate::dkim::*;

/// RFC 6376 s. 3.5
#[derive(Clone, Debug, PartialEq)]
pub struct DkimSignature<'hdr> {
    /// Version
    pub v: DkimVersion<'hdr>,
    /// Algorithm
    pub a: DkimAlgorithm<'hdr>,
    /// Signature data (base64)
    pub b: &'hdr str,
    /// Hash of canonicalized body part of the message as limited by the 'l='
    pub bh: &'hdr str,
    /// Message canonicalization informs the verifier of the type of canonicalization used to prepare the message for signing. See s.3.4
    pub c: Option<DkimCanonicalization<'hdr>>,
    /// The SDID claiming responsibility for an introduction of a message into the mail stream
    pub d: &'hdr str,
    /// Signed header fields separated by colon ':' - see 'h='
    pub h: &'hdr str,
    /// The Agent or User Identifier (AUID) on behalf of which the SDID is taking responsibility.
    pub i: Option<&'hdr str>,
    /// Body length limit - see misuse on RFC 6376 s. 8.2
    pub l: Option<&'hdr str>,
    /// Query methods - currently only DnsTxt
    pub q: Option<&'hdr str>,
    /// The selector subdividing the namespace for the "d=" (domain) tag
    pub s: &'hdr str,
    /// Recommended - Signature Timestamp
    pub t: Option<DkimTimestamp<'hdr>>,
    /// Recommended - Signature Expiration
    pub x: Option<DkimTimestamp<'hdr>>,
    /// Copied header fields
    pub z: Option<&'hdr str>,
}
