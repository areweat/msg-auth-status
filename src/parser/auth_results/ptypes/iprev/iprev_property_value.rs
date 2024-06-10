//! Parsing iprev property values

use super::{parse_comment, CommentToken};
use crate::error::AuthResultsError;
use logos::{Lexer, Logos};

//-----------------------------
// iprev policy.*
//-----------------------------

use super::IpRevPolicyPropertyKey;
use crate::iprev::ptypes::IpRevPolicy;

#[derive(Debug, Logos)]
pub enum IpRevPolicyPropertyValueToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    #[regex(r#"[^(\s\r\n\t;]+"#, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),

    #[regex(r"[\s\r\n\t]+", |lex| lex.slice(), priority = 3)]
    Whs(&'hdr str),
}

impl<'hdr> IpRevPolicy<'hdr> {
    fn from_parsed(pkey: &IpRevPolicyPropertyKey<'hdr>, val: &'hdr str) -> Self {
        match pkey {
            IpRevPolicyPropertyKey::IpRev => IpRevPolicy::IpRev(val),
            IpRevPolicyPropertyKey::Unknown(key) => IpRevPolicy::Unknown(key, val),
        }
    }
}

pub fn parse_iprev_policy_property_value<'hdr>(
    lexer: &mut Lexer<'hdr, IpRevPolicyPropertyValueToken<'hdr>>,
    property_key: &IpRevPolicyPropertyKey<'hdr>,
) -> Result<IpRevPolicy<'hdr>, AuthResultsError<'hdr>> {
    let mut cur_res: Option<IpRevPolicy<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(IpRevPolicyPropertyValueToken::MaybeValue(val)) => {
                cur_res = Some(IpRevPolicy::from_parsed(property_key, val));
                break;
            }
            Ok(IpRevPolicyPropertyValueToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(_comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
            }
            Ok(IpRevPolicyPropertyValueToken::Whs(_)) => {
                // cont
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "iprev_property_value",
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

    Err(AuthResultsError::RunAwayIpRevPropertyValue)
}

//-----------------------------
// iprev smtp.* (RFC broken)
//-----------------------------

use super::IpRevSmtpPropertyKey;
use crate::iprev::ptypes::IpRevSmtp;

#[derive(Debug, Logos)]
pub enum IpRevSmtpPropertyValueToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    #[regex(r#"[^(\s\r\n\t;]+"#, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),

    #[regex(r"[\s\r\n\t]+", |lex| lex.slice(), priority = 3)]
    Whs(&'hdr str),
}

impl<'hdr> IpRevSmtp<'hdr> {
    fn from_parsed(pkey: &IpRevSmtpPropertyKey<'hdr>, val: &'hdr str) -> Self {
        match pkey {
            IpRevSmtpPropertyKey::Unknown(key) => IpRevSmtp::Unknown(key, val),
        }
    }
}

pub fn parse_iprev_smtp_property_value<'hdr>(
    lexer: &mut Lexer<'hdr, IpRevSmtpPropertyValueToken<'hdr>>,
    property_key: &IpRevSmtpPropertyKey<'hdr>,
) -> Result<IpRevSmtp<'hdr>, AuthResultsError<'hdr>> {
    let mut cur_res: Option<IpRevSmtp<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(IpRevSmtpPropertyValueToken::MaybeValue(val)) => {
                cur_res = Some(IpRevSmtp::from_parsed(property_key, val));
                break;
            }
            Ok(IpRevSmtpPropertyValueToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(_comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
            }
            Ok(IpRevSmtpPropertyValueToken::Whs(_)) => {
                // cont
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "iprev_property_value",
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

    Err(AuthResultsError::RunAwayIpRevPropertyValue)
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_comment() {
        let mut lexer = IpRevPolicyPropertyValueToken::lexer("(foobar) value.foo");
        let res = parse_iprev_policy_property_value(&mut lexer, &IpRevPolicyPropertyKey::IpRev);

        assert_eq!(res, Ok(IpRevPolicy::IpRev("value.foo")));
    }
}
