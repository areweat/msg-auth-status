//! Parsing dkim property values

use crate::dkim::ptypes::DkimPolicy;
use crate::dkim::*;
use crate::error::AuthResultsError;

use super::DkimHeaderPropertyKey;
use super::DkimPolicyPropertyKey;
use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

//---------------------------------------
// DKIM header.xxx ptype values
//---------------------------------------

#[derive(Debug, Logos)]
pub enum DkimHeaderPropertyValueToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    #[regex(r#"[^(\s\r\n\t;]+"#, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),

    #[regex(r"[\s\r\n\t]+", |lex| lex.slice(), priority = 3)]
    #[allow(dead_code)]
    Whs(&'hdr str),
}

impl<'hdr> DkimHeader<'hdr> {
    fn from_parsed(pkey: &DkimHeaderPropertyKey<'hdr>, val: &'hdr str) -> Self {
        match pkey {
            DkimHeaderPropertyKey::TagD => DkimHeader::D(val),
            DkimHeaderPropertyKey::TagI => DkimHeader::I(val),
            DkimHeaderPropertyKey::TagB => DkimHeader::B(val),
            DkimHeaderPropertyKey::TagA => {
                let alg = match val {
                    "rsa-sha1" => DkimAlgorithm::Rsa_Sha1,
                    "rsa-sha256" => DkimAlgorithm::Rsa_Sha256,
                    "ed25519-sha256" => DkimAlgorithm::Ed25519_Sha256,
                    _ => DkimAlgorithm::Unknown(val),
                };
                DkimHeader::A(alg)
            }
            DkimHeaderPropertyKey::TagS => DkimHeader::S(val),
            DkimHeaderPropertyKey::Rfc5322From => DkimHeader::Rfc5322From(val), // not covered
            DkimHeaderPropertyKey::Unknown(key) => DkimHeader::Unknown(key, val),
        }
    }
}

pub fn parse_dkim_header_property_value<'hdr>(
    lexer: &mut Lexer<'hdr, DkimHeaderPropertyValueToken<'hdr>>,
    property_key: &DkimHeaderPropertyKey<'hdr>,
) -> Result<DkimHeader<'hdr>, AuthResultsError<'hdr>> {
    let mut cur_res: Option<DkimHeader<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(DkimHeaderPropertyValueToken::MaybeValue(val)) => {
                cur_res = Some(DkimHeader::from_parsed(property_key, val));
                break;
            }
            Ok(DkimHeaderPropertyValueToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(_comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
            }
            Ok(DkimHeaderPropertyValueToken::Whs(_)) => {
                // cont
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "dkim_header_property_value",
                    span_start: lexer.span().start,
                    span_end: lexer.span().end,
                    source: lexer.source(),
                    clipped_span: cut_span,
                    clipped_remaining: cut_slice,
                };
                return Err(AuthResultsError::ParsingDetailed(detail));
            }
        }
    }

    if let Some(value) = cur_res {
        return Ok(value);
    }

    Err(AuthResultsError::RunAwayDkimPropertyKey)
}

//---------------------------------------
// DKIM policy.xxx ptype values
//---------------------------------------

#[derive(Debug, Logos)]
pub enum DkimPolicyPropertyValueToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    #[regex(r"\s+", |lex| lex.slice(), priority = 2)]
    WhiteSpaces(&'hdr str),

    #[regex(r"\n+", |lex| lex.slice(), priority = 3)]
    LineFeeds(&'hdr str),

    #[regex(r"[A-Za-z0-9]+", |lex| lex.slice(), priority = 4)]
    MaybeValue(&'hdr str),
}

impl<'hdr> DkimPolicy<'hdr> {
    fn from_parsed(pkey: &DkimPolicyPropertyKey<'hdr>, val: &'hdr str) -> Self {
        match pkey {
            DkimPolicyPropertyKey::Unknown(key) => DkimPolicy::Unknown(key, val),
        }
    }
}

pub fn parse_dkim_policy_property_value<'hdr>(
    lexer: &mut Lexer<'hdr, DkimPolicyPropertyValueToken<'hdr>>,
    property_key: &DkimPolicyPropertyKey<'hdr>,
) -> Result<DkimPolicy<'hdr>, AuthResultsError<'hdr>> {
    let mut cur_res: Option<DkimPolicy<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(DkimPolicyPropertyValueToken::MaybeValue(val)) => {
                cur_res = Some(DkimPolicy::from_parsed(property_key, val));
                break;
            }
            Ok(DkimPolicyPropertyValueToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                let _comment = match parse_comment(&mut comment_lexer) {
                    Ok(comment) => comment,
                    Err(e) => return Err(e),
                };
                lexer.bump(comment_lexer.span().end);
            }
            Ok(DkimPolicyPropertyValueToken::WhiteSpaces(_)) => {
                // cont
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "dkim_policy_property_value",
                    span_start: lexer.span().start,
                    span_end: lexer.span().end,
                    source: lexer.source(),
                    clipped_span: cut_span,
                    clipped_remaining: cut_slice,
                };
                return Err(AuthResultsError::ParsingDetailed(detail));
            }
        }
    }

    if let Some(value) = cur_res {
        return Ok(value);
    }

    Err(AuthResultsError::RunAwayDkimPropertyKey)
}
