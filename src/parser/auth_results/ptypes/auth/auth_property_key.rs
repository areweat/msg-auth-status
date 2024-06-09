//! Parsing auth property types & values

use crate::error::AuthResultsError;

/// IANA Email Authentication Methods ptype / property Mapping stages
#[derive(Debug, PartialEq)]
pub enum AuthSmtpPropertyKey {
    MailFrom,
    Auth,
}

impl<'hdr> TryFrom<AuthSmtpPropertyKeyToken<'hdr>> for AuthSmtpPropertyKey {
    type Error = AuthResultsError;
    fn try_from(token: AuthSmtpPropertyKeyToken<'hdr>) -> Result<Self, Self::Error> {
        let okk = match token {
            AuthSmtpPropertyKeyToken::MailFrom => Self::MailFrom,
            AuthSmtpPropertyKeyToken::Auth => Self::Auth,
            _ => return Err(AuthResultsError::ParsePtypeBugInvalidProperty),
        };
        Ok(okk)
    }
}

//----------
// Parsing auth property
//----------

use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum AuthSmtpPropertyKeyToken<'hdr> {
    #[token("mailfrom", priority = 1)]
    MailFrom,

    #[token("auth", priority = 1)]
    Auth,

    #[token("(", priority = 2)]
    CommentStart,

    #[regex(r"\s+", |lex| lex.slice(), priority = 6)]
    WhiteSpaces(&'hdr str),
}

pub fn parse_auth_smtp_property_key<'hdr>(
    lexer: &mut Lexer<'hdr, AuthSmtpPropertyKeyToken<'hdr>>,
) -> Result<AuthSmtpPropertyKey, AuthResultsError> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(AuthSmtpPropertyKeyToken::MailFrom | AuthSmtpPropertyKeyToken::Auth) => {
                let property = token.map_err(|_| AuthResultsError::ParsePtypeBugPropertyGating)?;
                let mapped_property_res: Result<AuthSmtpPropertyKey, AuthResultsError> =
                    property.try_into();
                let mapped_property = mapped_property_res
                    .map_err(|_| AuthResultsError::ParsePtypeBugInvalidProperty)?;
                return Ok(mapped_property);
            }
            Ok(AuthSmtpPropertyKeyToken::WhiteSpaces(_)) => {
                // cont
            }
            Ok(AuthSmtpPropertyKeyToken::CommentStart) => {
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
                    "parse_auth_property_key -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
                    token,
                    lexer.span(),
                    lexer.source(),
                    cut_span,
	                cut_slice,
                );
            }
        }
    }
    Err(AuthResultsError::RunAwayAuthPropertyKey)
}
