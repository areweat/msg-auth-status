//! Parsing spf property values

use crate::error::AuthResultsError;
use crate::spf::ptypes::SpfSmtp;

use super::SpfSmtpPropertyKey;
use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum SpfSmtpPropertyValueToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    #[regex(r#"[^(\s\r\n\t;]+"#, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),

    #[regex(r"[\s\r\n\t]+", |lex| lex.slice(), priority = 3)]
    Whs(&'hdr str),
}

impl<'hdr> SpfSmtp<'hdr> {
    fn from_parsed(pkey: &SpfSmtpPropertyKey, val: &'hdr str) -> Self {
        match pkey {
            SpfSmtpPropertyKey::MailFrom => SpfSmtp::MailFrom(val),
            SpfSmtpPropertyKey::Helo => SpfSmtp::Helo(val),
        }
    }
}

pub fn parse_spf_smtp_property_value<'hdr>(
    lexer: &mut Lexer<'hdr, SpfSmtpPropertyValueToken<'hdr>>,
    property_key: &SpfSmtpPropertyKey,
) -> Result<SpfSmtp<'hdr>, AuthResultsError<'hdr>> {
    let mut cur_res: Option<SpfSmtp<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(SpfSmtpPropertyValueToken::MaybeValue(val)) => {
                cur_res = Some(SpfSmtp::from_parsed(property_key, val));
                break;
            }
            Ok(SpfSmtpPropertyValueToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                let _comment = match parse_comment(&mut comment_lexer) {
                    Ok(comment) => comment,
                    Err(e) => return Err(AuthResultsError::ParseComment(e)),
                };
                lexer.bump(comment_lexer.span().end);
            }
            Ok(SpfSmtpPropertyValueToken::Whs(_)) => {
                // cont
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "spf_property_value",
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

    Err(AuthResultsError::RunAwaySpfPropertyValue)
}
