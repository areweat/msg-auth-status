//! Parsing for DKIM-Signature using Logos

use logos::{Lexer, Logos};

use crate::dkim::*;

use crate::error::{DkimSignatureError, DkimTagValueError};

#[cfg(feature = "mail_parser")]
use mail_parser::HeaderValue;

#[derive(Debug, Logos)]
pub enum DkimFieldValueToken<'hdr> {
    #[regex(r"[^;]+", |lex| lex.slice(), priority = 1)]
    MaybeValue(&'hdr str),

    #[token(";", priority = 2)]
    FieldSep,
}

/// See RFC 6376 s. 3.5 - DKIM Tags
#[derive(Debug, Logos)]
#[logos(skip r"[ \t\r\n]+")]
pub enum DkimFieldKeyToken<'hdr> {
    #[token("v", priority = 1)]
    TagV, // Version - RFC 6376 only defines "1"

    #[token("a", priority = 1)]
    TagA,

    #[token("bh", priority = 1)]
    TagBh,

    #[token("c", priority = 1)]
    TagC,

    #[token("d", priority = 1)]
    TagD,

    #[token("h", priority = 1)]
    TagH,

    #[token("i", priority = 1)]
    TagI,

    #[token("l", priority = 1)]
    TagL,

    #[token("q", priority = 1)]
    TagQ,

    #[token("s", priority = 1)]
    TagS,

    #[token("t", priority = 1)]
    TagT,

    #[token("x", priority = 1)]
    TagX,

    #[token("z", priority = 1)]
    TagZ,

    #[token(";", priority = 1)]
    FieldSep,

    #[token("=", priority = 1)]
    Equal,

    // Must not conflict with "b"
    #[token("b", priority = 2)]
    TagB,

    // Allows everything else alpha than above as unknown tags
    #[regex(r"(b[a-gi-z]|[efgjkmnopryuv][a-z]+)", |lex| lex.slice(), priority = 3)]
    MaybeTag(&'hdr str),
}

#[derive(Clone, Debug, PartialEq)]
pub enum DkimTagChoice<'hdr> {
    V,
    A,
    B,
    Bh,
    C,
    D,
    H,
    I,
    L,
    Q,
    S,
    T,
    X,
    Z,
    // RFC 6376 s. 3.2 Unrecognised tags MUST be ignored
    Unknown(&'hdr str),
}

impl<'hdr> DkimTagChoice<'hdr> {
    fn from_token(token: DkimFieldKeyToken<'hdr>) -> Option<Self> {
        let ret = match token {
            DkimFieldKeyToken::TagV => Self::V,
            DkimFieldKeyToken::TagA => Self::A,
            DkimFieldKeyToken::TagB => Self::B,
            DkimFieldKeyToken::TagBh => Self::Bh,
            DkimFieldKeyToken::TagC => Self::C,
            DkimFieldKeyToken::TagD => Self::D,
            DkimFieldKeyToken::TagH => Self::H,
            DkimFieldKeyToken::TagI => Self::I,
            DkimFieldKeyToken::TagL => Self::L,
            DkimFieldKeyToken::TagQ => Self::Q,
            DkimFieldKeyToken::TagS => Self::S,
            DkimFieldKeyToken::TagT => Self::T,
            DkimFieldKeyToken::TagX => Self::X,
            DkimFieldKeyToken::TagZ => Self::Z,
            DkimFieldKeyToken::MaybeTag(tag) => Self::Unknown(tag),
            _ => return None,
        };
        Some(ret)
    }
}

#[derive(Debug, PartialEq)]
enum Stage<'hdr> {
    WantTag,
    WantEq(DkimTagChoice<'hdr>),
}

// Intermediary Parsed structure to final DkimSignature
// Final DkimSignature validates if any missing fields
#[derive(Debug, Default, PartialEq)]
struct ParsedDkimSignature<'hdr> {
    /// Version
    pub v: Option<DkimVersion<'hdr>>,
    /// Algorithm
    pub a: Option<DkimAlgorithm<'hdr>>,
    /// Signature data (base64)
    pub b: Option<&'hdr str>,
    /// Hash of canonicalized body part of the message as limited by the 'l='
    pub bh: Option<&'hdr str>,
    /// Message canonicalization informs the verifier of the type of canonicalization used to prepare the message for signing. See s.3.4
    pub c: Option<DkimCanonicalization<'hdr>>,
    /// The SDID claiming responsibility for an introduction of a message into the mail stream
    pub d: Option<&'hdr str>,
    /// Signed header fields separated by colon ':' - see 'h='
    pub h: Option<&'hdr str>,
    /// The Agent or User Identifier (AUID) on behalf of which the SDID is taking responsibility.
    pub i: Option<&'hdr str>,
    /// Body length limit - see misuse on RFC 6376 s. 8.2
    pub l: Option<&'hdr str>,
    /// Query methods - currently only DnsTxt
    pub q: Option<&'hdr str>,
    /// The selector subdividing the namespace for the "d=" (domain) tag
    pub s: Option<&'hdr str>,
    /// Recommended - Signature Timestamp
    pub t: Option<DkimTimestamp<'hdr>>,
    /// Recommended - Signature Expiration
    pub x: Option<DkimTimestamp<'hdr>>,
    /// Copied header fields
    pub z: Option<&'hdr str>,
    /// Raw unparsed
    pub raw: Option<&'hdr str>,
}

impl<'hdr> ParsedDkimSignature<'hdr> {
    fn add_tag_value(
        &mut self,
        tag: DkimTagChoice<'hdr>,
        val: &'hdr str,
    ) -> Result<(), DkimTagValueError> {
        match tag {
            DkimTagChoice::V => self.v = Some(val.try_into()?),
            DkimTagChoice::A => self.a = Some(val.try_into()?),
            DkimTagChoice::B => self.b = Some(val),
            DkimTagChoice::Bh => self.bh = Some(val),
            DkimTagChoice::C => self.c = Some(val.try_into()?),
            DkimTagChoice::D => self.d = Some(val),
            DkimTagChoice::H => self.h = Some(val),
            DkimTagChoice::I => self.i = Some(val),
            DkimTagChoice::L => self.l = Some(val),
            DkimTagChoice::Q => self.q = Some(val),
            DkimTagChoice::S => self.s = Some(val),
            DkimTagChoice::T => self.t = Some(val.try_into()?),
            DkimTagChoice::X => self.x = Some(val.try_into()?),
            DkimTagChoice::Z => self.z = Some(val),
            // RFC 6376 s. 3.2 Unrecognised tags MUST be ignored
            DkimTagChoice::Unknown(_) => {}
        }
        Ok(())
    }
}

// TODO: It would be helpful to highlight all errors
impl<'hdr> TryFrom<ParsedDkimSignature<'hdr>> for DkimSignature<'hdr> {
    type Error = DkimSignatureError<'hdr>;

    fn try_from(p: ParsedDkimSignature<'hdr>) -> Result<Self, Self::Error> {
        // Required fields must be present
        let version = match p.v {
            Some(val) => val,
            None => return Err(DkimSignatureError::MissingVersion),
        };
        let algorithm = match p.a {
            Some(val) => val,
            None => return Err(DkimSignatureError::MissingAlgorithm),
        };
        let signature = match p.b {
            Some(val) => val,
            None => return Err(DkimSignatureError::MissingSignature),
        };
        let body_hash = match p.bh {
            Some(val) => val,
            None => return Err(DkimSignatureError::MissingBodyHash),
        };
        let responsible_sdid = match p.d {
            Some(val) => val,
            None => return Err(DkimSignatureError::MissingResponsibleSdid),
        };
        let signed_header_fields = match p.h {
            Some(val) => val,
            None => return Err(DkimSignatureError::MissingSignedHeaderFields),
        };
        let selector = match p.s {
            Some(val) => val,
            None => return Err(DkimSignatureError::MissingSelector),
        };
        // Optional c, i, l, q, s, t, x, z,
        let c = p.c;
        let i = p.i;
        let l = p.l;
        let q = p.q;
        let t = p.t;
        let x = p.x;
        let z = p.z;
        let raw = p.raw;
        Ok(Self {
            v: version,
            a: algorithm,
            b: signature,
            bh: body_hash,
            d: responsible_sdid,
            h: signed_header_fields,
            s: selector,
            c,
            i,
            l,
            q,
            t,
            x,
            z,
            raw,
        })
    }
}

impl<'hdr> TryFrom<&'hdr HeaderValue<'hdr>> for DkimSignature<'hdr> {
    type Error = DkimSignatureError<'hdr>;

    fn try_from(hval: &'hdr HeaderValue<'hdr>) -> Result<Self, Self::Error> {
        let text = match hval.as_text() {
            None => return Err(DkimSignatureError::NoTagFound),
            Some(text) => text,
        };

        let mut tag_lexer = DkimFieldKeyToken::lexer(text);
        let mut stage = Stage::WantTag;
        let mut res = ParsedDkimSignature {
            raw: Some(text),
            ..Default::default()
        };

        while let Some(token) = tag_lexer.next() {
            match token {
                Ok(DkimFieldKeyToken::Equal) if stage != Stage::WantTag => {
                    stage = match stage {
                        Stage::WantEq(ref key_tag) => {
                            let mut value_lexer: Lexer<'hdr, DkimFieldValueToken<'hdr>> =
                                tag_lexer.morph();

                            for value_token in value_lexer.by_ref() {
                                match value_token {
                                    Ok(DkimFieldValueToken::MaybeValue(value)) => {
                                        res.add_tag_value(key_tag.clone(), value)?;
                                    }
                                    Ok(DkimFieldValueToken::FieldSep) => {
                                        break;
                                    }
                                    Err(_) => return Err(DkimSignatureError::ParseValueUnmatch),
                                }
                            }
                            tag_lexer = value_lexer.morph();
                            Stage::WantTag
                        }
                        _ => return Err(DkimSignatureError::UnexpectedEqual),
                    };
                }
                Ok(maybe_tag_token) if stage == Stage::WantTag => {
                    let current_tag = DkimTagChoice::from_token(maybe_tag_token);
                    stage = match current_tag {
                        None => return Err(DkimSignatureError::NoTagFound),
                        Some(tag) => Stage::WantEq(tag),
                    };
                }
                _ => {
                    let cut_slice = &tag_lexer.source()[tag_lexer.span().start..];
                    let cut_span =
                        &tag_lexer.source()[tag_lexer.span().start..tag_lexer.span().end];

                    let detail = crate::error::ParsingDetail {
                        component: "parse_dkim_signature",
                        span_start: tag_lexer.span().start,
                        span_end: tag_lexer.span().end,
                        source: tag_lexer.source(),
                        clipped_span: cut_span,
                        clipped_remaining: cut_slice,
                    };

                    return Err(DkimSignatureError::ParsingDetailed(detail));
                }
            }
        }
        res.try_into()
    }
}
