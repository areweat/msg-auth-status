//! Parsing auth property types & values
//! https://www.iana.org/assignments/email-auth/email-auth.xhtml

use crate::auth::*;

use super::ResultCodeError;

/// IANA Email Authentication Methods ptype / property Mapping stages
#[derive(Debug, PartialEq)]
pub enum AuthSmtpPropertyKey {
    MailFrom,
    Auth,
}

impl<'hdr> TryFrom<AuthSmtpPropertyKeyToken<'hdr>> for AuthSmtpPropertyKey {
    type Error = ResultCodeError;
    fn try_from(token: AuthSmtpPropertyKeyToken<'hdr>) -> Result<Self, Self::Error> {
        let okk = match token {
            AuthSmtpPropertyKeyToken::MailFrom => Self::MailFrom,
            AuthSmtpPropertyKeyToken::Auth => Self::Auth,
            _ => return Err(ResultCodeError::ParsePtypeBugInvalidProperty),
        };
        Ok(okk)
    }
}

//----------
// Parsing auth property
// https://www.iana.org/assignments/email-auth/email-auth.xhtml
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
) -> Result<AuthSmtpPropertyKey, ResultCodeError> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(AuthSmtpPropertyKeyToken::MailFrom | AuthSmtpPropertyKeyToken::Auth) => {
                let property = token.map_err(|_| ResultCodeError::ParsePtypeBugPropertyGating)?;
                let mapped_property_res: Result<AuthSmtpPropertyKey, ResultCodeError> =
                    property.try_into();
                let mapped_property = mapped_property_res
                    .map_err(|_| ResultCodeError::ParsePtypeBugInvalidProperty)?;
                return Ok(mapped_property);
            }
            Ok(AuthSmtpPropertyKeyToken::WhiteSpaces(_)) => {
                // cont
            }
            Ok(AuthSmtpPropertyKeyToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
                //*lexer = X::lexer(comment_lexer.remainder());
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
    Err(ResultCodeError::RunAwayAuthPropertyKey)
}
