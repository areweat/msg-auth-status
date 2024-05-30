//! Parsing auth property values

use crate::auth::ptypes::AuthSmtp;
use crate::auth::*;

use super::ResultCodeError;

use super::AuthSmtpPropertyKey;
use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum AuthSmtpPropertyValueToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    #[regex(r#"[^\s;]+"#, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),

    Dummy(&'hdr str),
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
) -> Result<AuthSmtp<'hdr>, ResultCodeError> {
    let mut value_captured = false;
    let mut cur_res: Option<AuthSmtp<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(AuthSmtpPropertyValueToken::MaybeValue(val)) if value_captured == false => {
                cur_res = Some(AuthSmtp::from_parsed(property_key, val));
                value_captured = true;
                break;
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                panic!(
                    "parse_auth_smtp_property_value -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
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

    Err(ResultCodeError::RunAwayAuthPropertyValue)
}
