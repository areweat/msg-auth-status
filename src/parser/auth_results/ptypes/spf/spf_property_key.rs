//! Parsing spf property types & values
//! https://www.iana.org/assignments/email-auth/email-auth.xhtml

use crate::spf::*;

use super::ResultCodeError;

/// IANA Email Authentication Methods ptype / property Mapping stages
#[derive(Debug, PartialEq)]
pub enum SpfSmtpPropertyKey {
    MailFrom,
    Helo,
}

impl<'hdr> TryFrom<SpfSmtpPropertyKeyToken<'hdr>> for SpfSmtpPropertyKey {
    type Error = ResultCodeError;
    fn try_from(token: SpfSmtpPropertyKeyToken<'hdr>) -> Result<Self, Self::Error> {
        let okk = match token {
            SpfSmtpPropertyKeyToken::MailFrom => Self::MailFrom,
            SpfSmtpPropertyKeyToken::Helo => Self::Helo,
            _ => return Err(ResultCodeError::ParsePtypeBugInvalidProperty),
        };
        Ok(okk)
    }
}

//----------
// Parsing spf property
// https://www.iana.org/assignments/email-auth/email-auth.xhtml
//----------

use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum SpfSmtpPropertyKeyToken<'hdr> {
    #[token("mailfrom", priority = 1)]
    MailFrom,

    #[token("helo", priority = 1)]
    Helo,

    #[token("(", priority = 2)]
    CommentStart,

    #[regex(r"\s+", |lex| lex.slice(), priority = 6)]
    WhiteSpaces(&'hdr str),
}

pub fn parse_spf_smtp_property_key<'hdr>(
    lexer: &mut Lexer<'hdr, SpfSmtpPropertyKeyToken<'hdr>>,
) -> Result<SpfSmtpPropertyKey, ResultCodeError> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(SpfSmtpPropertyKeyToken::MailFrom | SpfSmtpPropertyKeyToken::Helo) => {
                let property = token.map_err(|_| ResultCodeError::ParsePtypeBugPropertyGating)?;
                let mapped_property_res: Result<SpfSmtpPropertyKey, ResultCodeError> =
                    property.try_into();
                let mapped_property = mapped_property_res
                    .map_err(|_| ResultCodeError::ParsePtypeBugInvalidProperty)?;
                return Ok(mapped_property);
            }
            Ok(SpfSmtpPropertyKeyToken::WhiteSpaces(_)) => {
                // cont
            }
            Ok(SpfSmtpPropertyKeyToken::CommentStart) => {
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
                    "parse_spf_property_key -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
                    token,
                    lexer.span(),
                    lexer.source(),
                    cut_span,
	                cut_slice,
                );
            }
        }
    }
    Err(ResultCodeError::RunAwaySpfPropertyKey)
}
