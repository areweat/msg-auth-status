//! Parsing dkim property types & values

use crate::error::AuthResultsError;

/// IANA Email Authentication Methods ptype / property Mapping stages
#[derive(Debug, PartialEq)]
pub enum DkimHeaderPropertyKey {
    TagD,
    TagI,
    TagB,
    TagA,
    TagS,
    Rfc5322From,
}

impl<'hdr> TryFrom<DkimHeaderPropertyKeyToken<'hdr>> for DkimHeaderPropertyKey {
    type Error = AuthResultsError;
    fn try_from(token: DkimHeaderPropertyKeyToken<'hdr>) -> Result<Self, Self::Error> {
        let okk = match token {
            DkimHeaderPropertyKeyToken::TagD => Self::TagD,
            DkimHeaderPropertyKeyToken::TagI => Self::TagI,
            DkimHeaderPropertyKeyToken::TagB => Self::TagB,
            DkimHeaderPropertyKeyToken::TagA => Self::TagA,
            DkimHeaderPropertyKeyToken::TagS => Self::TagS,
            DkimHeaderPropertyKeyToken::Rfc5322From => Self::Rfc5322From,
            _ => return Err(AuthResultsError::ParsePtypeBugInvalidProperty),
        };
        Ok(okk)
    }
}

#[derive(Debug, PartialEq)]
pub enum DkimPolicyPropertyKey<'hdr> {
    Unknown(&'hdr str),
}

impl<'hdr> TryFrom<DkimPolicyPropertyKeyToken<'hdr>> for DkimPolicyPropertyKey<'hdr> {
    type Error = AuthResultsError;
    fn try_from(token: DkimPolicyPropertyKeyToken<'hdr>) -> Result<Self, Self::Error> {
        let okk = match token {
            DkimPolicyPropertyKeyToken::Unknown(val) => Self::Unknown(val),
            _ => return Err(AuthResultsError::ParsePtypeBugInvalidProperty),
        };
        Ok(okk)
    }
}

//----------
// Parsing dkim property
//----------

use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum DkimHeaderPropertyKeyToken<'hdr> {
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

    #[token("(", priority = 2)]
    CommentStart,

    #[regex(r#""[a-zA-Z0-9]+""#, |lex| lex.slice(), priority = 3)]
    Unknown(&'hdr str),

    #[regex(r"\s+", |lex| lex.slice(), priority = 6)]
    WhiteSpaces(&'hdr str),
}

pub fn parse_dkim_header_property_key<'hdr>(
    lexer: &mut Lexer<'hdr, DkimHeaderPropertyKeyToken<'hdr>>,
) -> Result<DkimHeaderPropertyKey, AuthResultsError> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(
                DkimHeaderPropertyKeyToken::TagD
                | DkimHeaderPropertyKeyToken::TagI
                | DkimHeaderPropertyKeyToken::TagB
                | DkimHeaderPropertyKeyToken::TagA
                | DkimHeaderPropertyKeyToken::TagS
                | DkimHeaderPropertyKeyToken::Rfc5322From,
            ) => {
                let property = token.map_err(|_| AuthResultsError::ParsePtypeBugPropertyGating)?;
                let mapped_property_res: Result<DkimHeaderPropertyKey, AuthResultsError> =
                    property.try_into();
                let mapped_property = mapped_property_res
                    .map_err(|_| AuthResultsError::ParsePtypeBugInvalidProperty)?;
                return Ok(mapped_property);
            }
            Ok(DkimHeaderPropertyKeyToken::WhiteSpaces(_)) => {
                // cont
            }
            Ok(DkimHeaderPropertyKeyToken::CommentStart) => {
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

                panic!(
                    "parse_dkim_header_property_key -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
                    token,
                    lexer.span(),
                    lexer.source(),
                    cut_span,
	                cut_slice,
                );
            }
        }
    }
    Err(AuthResultsError::RunAwayDkimPropertyKey)
}

//----------
// Parsing dkim policy property
//----------

#[derive(Debug, Logos)]
pub enum DkimPolicyPropertyKeyToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    #[regex(r"[a-zA-Z0-9]+", |lex| lex.slice(), priority = 2)]
    Unknown(&'hdr str),

    #[regex(r"\s+", |lex| lex.slice(), priority = 3)]
    WhiteSpaces(&'hdr str),
}

pub fn parse_dkim_policy_property_key<'hdr>(
    lexer: &mut Lexer<'hdr, DkimPolicyPropertyKeyToken<'hdr>>,
) -> Result<DkimPolicyPropertyKey<'hdr>, AuthResultsError> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(DkimPolicyPropertyKeyToken::Unknown(_)) => {
                let property = token.map_err(|_| AuthResultsError::ParsePtypeBugPropertyGating)?;
                let mapped_property_res: Result<DkimPolicyPropertyKey<'hdr>, AuthResultsError> =
                    property.try_into();
                let mapped_property = mapped_property_res
                    .map_err(|_| AuthResultsError::ParsePtypeBugInvalidProperty)?;
                return Ok(mapped_property);
            }
            Ok(DkimPolicyPropertyKeyToken::WhiteSpaces(_)) => {
                // cont
            }
            Ok(DkimPolicyPropertyKeyToken::CommentStart) => {
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

                panic!(
                    "parse_dkim_policy_property_key -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
                    token,
                    lexer.span(),
                    lexer.source(),
                    cut_span,
	                cut_slice,
                );
            }
        }
    }
    Err(AuthResultsError::RunAwayDkimPropertyKey)
}
