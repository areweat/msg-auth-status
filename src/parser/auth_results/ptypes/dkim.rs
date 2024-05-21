//! DKIM Property types or 'ptype' per RFC 8601 s. 2.7.1
//!
//! IANA Maintains the registry for all the possible Parameters
//! https://www.iana.org/assignments/dkim-parameters/dkim-parameters.xhtml
//!
//! DKIM-Signature Tag Specifications are defined in RFC 6376 s. 7.2
//!
//! Also see s. 7.10 for the DKIM-Signature field

use crate::dkim::*;

#[derive(Debug)]
pub enum DkimProperty<'hdr> {
    Header(DkimHeader<'hdr>),
}

/// IANA Email Authentication Methods ptype / property Mapping stages
#[derive(Debug)]
pub enum DkimPropertyKey {
    TagD,
    TagI,
    TagB,
    TagA,
    TagS,
    Rfc5322From,
}

/// The 'q' Tag - see RFC 6376 s. 3.5
pub enum DkimQueryMethod<'hdr> {
    /// Domain Name System (DNS)
    Dns,
    /// Unknown
    Unknown(&'hdr str),
}

/// See RFC 6376 s. 3.5
#[derive(Debug)]
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
    C(DKimCanonicalization<'hdr>),
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
}

//----------
// Parsing dkim property & val
// https://www.iana.org/assignments/email-auth/email-auth.xhtml
//----------

use super::ResultCodeError;
use super::ResultCodeError;
use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum DkimPropertyKeyToken<'hdr> {
    #[token("(", priority = 2)]
    CommentStart,

    #[token("d", priority = 1)]
    TagD,

    #[token("i", priority = 1)]
    TagI,

    #[token("b", priority = 1)]
    TagB,

    #[token("a", priority = 1)]
    TagA,            

    #[token("s", priority = 1)]
    TagS,

    #[token("from", priority = 1)]
    Rfc5322From,
}

pub fn parse_dkim_property_key<'hdr>(
    lexer: &mut Lexer<'hdr, DkimPropertyToken<'hdr>>,
) -> Result<DkimPtype, ResultCodeError> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(DkimPropertyKeyToken::TagD | DkimPropertyKeyToken::TagI | DkimPropertyKeyToken::TagB | DkimPropertyKeyToken::TagA | DkimPropertyKeyToken::TagS | DkimPropertyKeyToken::Rfc5322From) {
                let property = token.map_err(|_| ResultCodeError::ParsePtypeBugPropertyGating)?;
                let mapped_property_res: Result<DkimPropertyKey, ResultCodeError> = property.try_into();
                let mapped_property = mapped.property_res.map_err(ResultCodeError::ParsePtypeBugInvalidProperty)?;
                return Ok(mapped_property);
            },
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start .. lexer.span().end];

                panic!(
                    "parse_dkim_property_key({:?}) -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
                    token,
                    lexer.span(),
                    lexer.source(),
                    cut_span,
	                cut_slice,
                );
            }
        }
    }
    Err(ResultCodeError::RunAwayDkimPropertyKey)
}
