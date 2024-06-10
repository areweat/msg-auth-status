//! Parsing spf property types & values

use crate::error::AuthResultsError;

/// IANA Email Authentication Methods ptype / property Mapping stages
#[derive(Debug, PartialEq)]
pub enum SpfSmtpPropertyKey {
    MailFrom,
    Helo,
}

impl<'hdr> TryFrom<SpfSmtpPropertyKeyToken<'hdr>> for SpfSmtpPropertyKey {
    type Error = AuthResultsError<'hdr>;
    fn try_from(token: SpfSmtpPropertyKeyToken<'hdr>) -> Result<Self, Self::Error> {
        let okk = match token {
            SpfSmtpPropertyKeyToken::MailFrom => Self::MailFrom,
            SpfSmtpPropertyKeyToken::Helo => Self::Helo,
            _ => return Err(AuthResultsError::ParsePtypeBugInvalidProperty),
        };
        Ok(okk)
    }
}

//----------
// Parsing spf property
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
) -> Result<SpfSmtpPropertyKey, AuthResultsError<'hdr>> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(SpfSmtpPropertyKeyToken::MailFrom | SpfSmtpPropertyKeyToken::Helo) => {
                let property = token.map_err(|_| AuthResultsError::ParsePtypeBugPropertyGating)?;
                let mapped_property_res: Result<SpfSmtpPropertyKey, AuthResultsError<'hdr>> =
                    property.try_into();
                let mapped_property = mapped_property_res
                    .map_err(|_| AuthResultsError::ParsePtypeBugInvalidProperty)?;
                return Ok(mapped_property);
            }
            Ok(SpfSmtpPropertyKeyToken::WhiteSpaces(_)) => {
                // cont
            }
            Ok(SpfSmtpPropertyKeyToken::CommentStart) => {
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
                    component: "spf_property_key",
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
    Err(AuthResultsError::RunAwaySpfPropertyKey)
}
