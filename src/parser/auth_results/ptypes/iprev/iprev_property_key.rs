//! Parsing iprev property types & values

use super::{parse_comment, CommentToken};
use crate::error::AuthResultsError;
use logos::{Lexer, Logos};

//------------------------------
// iprev.policy RFC
//------------------------------

#[derive(Debug, PartialEq)]
pub enum IpRevPolicyPropertyKey<'hdr> {
    IpRev,
    Unknown(&'hdr str),
}

impl<'hdr> TryFrom<IpRevPolicyPropertyKeyToken<'hdr>> for IpRevPolicyPropertyKey<'hdr> {
    type Error = AuthResultsError<'hdr>;
    fn try_from(token: IpRevPolicyPropertyKeyToken<'hdr>) -> Result<Self, Self::Error> {
        let okk = match token {
            IpRevPolicyPropertyKeyToken::IpRev => Self::IpRev,
            IpRevPolicyPropertyKeyToken::Unknown(key) => Self::Unknown(key),
            _ => return Err(AuthResultsError::ParsePtypeBugInvalidProperty),
        };
        Ok(okk)
    }
}

#[derive(Debug, Logos)]
pub enum IpRevPolicyPropertyKeyToken<'hdr> {
    #[token("iprev", priority = 100)]
    IpRev,

    #[token("(", priority = 2)]
    CommentStart,

    #[regex(r"[a-zA-Z_-]+", priority = 1)]
    Unknown(&'hdr str),

    #[regex(r"\s+", |lex| lex.slice(), priority = 6)]
    WhiteSpaces(&'hdr str),
}

pub fn parse_iprev_policy_property_key<'hdr>(
    lexer: &mut Lexer<'hdr, IpRevPolicyPropertyKeyToken<'hdr>>,
) -> Result<IpRevPolicyPropertyKey<'hdr>, AuthResultsError<'hdr>> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(IpRevPolicyPropertyKeyToken::IpRev | IpRevPolicyPropertyKeyToken::Unknown(_)) => {
                let property = token.map_err(|_| AuthResultsError::ParsePtypeBugPropertyGating)?;
                let mapped_property_res: Result<
                    IpRevPolicyPropertyKey<'hdr>,
                    AuthResultsError<'hdr>,
                > = property.try_into();
                let mapped_property = mapped_property_res
                    .map_err(|_| AuthResultsError::ParsePtypeBugInvalidProperty)?;
                return Ok(mapped_property);
            }
            Ok(IpRevPolicyPropertyKeyToken::WhiteSpaces(_)) => {
                // cont
            }
            Ok(IpRevPolicyPropertyKeyToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(_comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "iprev_property_key",
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
    Err(AuthResultsError::RunAwayIpRevPropertyKey)
}

//------------------------------
// iprev.smtp non-RFC
//------------------------------

#[derive(Debug, PartialEq)]
pub enum IpRevSmtpPropertyKey<'hdr> {
    Unknown(&'hdr str),
}

impl<'hdr> TryFrom<IpRevSmtpPropertyKeyToken<'hdr>> for IpRevSmtpPropertyKey<'hdr> {
    type Error = AuthResultsError<'hdr>;
    fn try_from(token: IpRevSmtpPropertyKeyToken<'hdr>) -> Result<Self, Self::Error> {
        let okk = match token {
            IpRevSmtpPropertyKeyToken::Unknown(key) => Self::Unknown(key),
            _ => return Err(AuthResultsError::ParsePtypeBugInvalidProperty),
        };
        Ok(okk)
    }
}

#[derive(Debug, Logos)]
pub enum IpRevSmtpPropertyKeyToken<'hdr> {
    #[regex(r"[a-z0-9-_]+", |lex| lex.slice(), priority = 1)]
    Unknown(&'hdr str),

    #[token("(", priority = 2)]
    CommentStart,

    #[regex(r"\s+", |lex| lex.slice(), priority = 6)]
    WhiteSpaces(&'hdr str),
}

pub fn parse_iprev_smtp_property_key<'hdr>(
    lexer: &mut Lexer<'hdr, IpRevSmtpPropertyKeyToken<'hdr>>,
) -> Result<IpRevSmtpPropertyKey<'hdr>, AuthResultsError<'hdr>> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(IpRevSmtpPropertyKeyToken::Unknown(_)) => {
                let property = token.map_err(|_| AuthResultsError::ParsePtypeBugPropertyGating)?;
                let mapped_property_res: Result<
                    IpRevSmtpPropertyKey<'hdr>,
                    AuthResultsError<'hdr>,
                > = property.try_into();
                let mapped_property = mapped_property_res
                    .map_err(|_| AuthResultsError::ParsePtypeBugInvalidProperty)?;
                return Ok(mapped_property);
            }
            Ok(IpRevSmtpPropertyKeyToken::WhiteSpaces(_)) => {
                // cont
            }
            Ok(IpRevSmtpPropertyKeyToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(_comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "iprev_property_key",
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
    Err(AuthResultsError::RunAwayIpRevPropertyKey)
}
