//! Parsing auth property values

use crate::auth::ptypes::AuthSmtp;
use crate::error::AuthResultsError;

use super::AuthSmtpPropertyKey;
use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum AuthSmtpPropertyValueToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    #[regex(r#"[^(\s\r\n\t;]+"#, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),

    #[regex(r"[\s\r\n\t]+", |lex| lex.slice(), priority = 3)]
    Whs(&'hdr str),
}

impl<'hdr> AuthSmtp<'hdr> {
    fn from_parsed(pkey: &AuthSmtpPropertyKey, val: &'hdr str) -> Self {
        match pkey {
            AuthSmtpPropertyKey::MailFrom => AuthSmtp::MailFrom(val),
            AuthSmtpPropertyKey::Auth => AuthSmtp::Auth(val),
        }
    }
}

pub fn parse_auth_smtp_property_value<'hdr>(
    lexer: &mut Lexer<'hdr, AuthSmtpPropertyValueToken<'hdr>>,
    property_key: &AuthSmtpPropertyKey,
) -> Result<AuthSmtp<'hdr>, AuthResultsError<'hdr>> {
    let mut cur_res: Option<AuthSmtp<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(AuthSmtpPropertyValueToken::MaybeValue(val)) => {
                cur_res = Some(AuthSmtp::from_parsed(property_key, val));
                break;
            }
            Ok(AuthSmtpPropertyValueToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(_comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
            }
            Ok(AuthSmtpPropertyValueToken::Whs(_)) => {
                // cont
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "auth_property_value",
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

    Err(AuthResultsError::RunAwayAuthPropertyValue)
}
