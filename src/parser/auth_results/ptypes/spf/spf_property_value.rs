//! Parsing spf property values

use crate::spf::ptypes::SpfSmtp;
use crate::spf::*;

use super::ResultCodeError;

use super::SpfSmtpPropertyKey;
use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum SpfSmtpPropertyValueToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    #[regex(r#"[^\s;]+"#, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),

    Dummy(&'hdr str),
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
) -> Result<SpfSmtp<'hdr>, ResultCodeError> {
    let mut value_captured = false;
    let mut cur_res: Option<SpfSmtp<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(SpfSmtpPropertyValueToken::MaybeValue(val)) if value_captured == false => {
                cur_res = Some(SpfSmtp::from_parsed(property_key, val));
                value_captured = true;
                break;
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                panic!(
                    "parse_spf_smtp_property_value -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
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

    Err(ResultCodeError::RunAwaySpfPropertyValue)
}
