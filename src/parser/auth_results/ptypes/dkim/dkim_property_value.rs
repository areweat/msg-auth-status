//! Parsing dkim property values

use crate::dkim::ptypes::DkimHeader;
use crate::dkim::ptypes::DkimPolicy;
use crate::dkim::*;

use super::ResultCodeError;

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

    #[regex(r#"[^\s;]+"#, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),

    #[regex(r"\s+", |lex| lex.slice(), priority = 3)]
    WhiteSpaces(&'hdr str),
}

impl<'hdr> DkimHeader<'hdr> {
    fn from_parsed(pkey: &DkimHeaderPropertyKey, val: &'hdr str) -> Self {
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
        }
    }
}

pub fn parse_dkim_header_property_value<'hdr>(
    lexer: &mut Lexer<'hdr, DkimHeaderPropertyValueToken<'hdr>>,
    property_key: &DkimHeaderPropertyKey,
) -> Result<DkimHeader<'hdr>, ResultCodeError> {
    let mut value_captured = false;
    let mut cur_res: Option<DkimHeader<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(DkimHeaderPropertyValueToken::MaybeValue(val)) if value_captured == false => {
                cur_res = Some(DkimHeader::from_parsed(property_key, val));
                value_captured = true;
                break;
            }
            Ok(DkimHeaderPropertyValueToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
                //*lexer = X::lexer(comment_lexer.remainder());
            }
            Ok(DkimHeaderPropertyValueToken::WhiteSpaces(_)) => {
                // cont
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                panic!(
                    "parse_dkim_header_property_value -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
                    token,
                    lexer.span(),
                    lexer.source(),
                    cut_span,
	                cut_slice,
                );
            }
        }
    }

    if let Some(value) = cur_res {
        return Ok(value);
    }

    Err(ResultCodeError::RunAwayDkimPropertyKey)
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
) -> Result<DkimPolicy<'hdr>, ResultCodeError> {
    let mut value_captured = false;
    let mut cur_res: Option<DkimPolicy<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(DkimPolicyPropertyValueToken::MaybeValue(val)) if value_captured == false => {
                cur_res = Some(DkimPolicy::from_parsed(property_key, val));
                value_captured = true;
                break;
            }
            Ok(DkimPolicyPropertyValueToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                let comment = match parse_comment(&mut comment_lexer) {
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

                panic!(
                    "parse_dkim_policy_property_value -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
                    token,
                    lexer.span(),
                    lexer.source(),
                    cut_span,
	                cut_slice,
                );
            }
        }
    }

    if let Some(value) = cur_res {
        return Ok(value);
    }

    Err(ResultCodeError::RunAwayDkimPropertyKey)
}
