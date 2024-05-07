//! policy ptype parsing - which is cursed
//!
//! This field is messy - RFC8601 admits that it has never been used
//! This will make b7 example work but this may not work given
//! RFC is very ambigious about it
//!
//! It should be something like this:
//! dkim=fail policy.dkim-rules=unsigned-subject
//!
//! But example does not follow the right definition but supposedly
//! it should be legal .. who knows

use super::ResultCodeError;

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
#[logos(skip r"[ \r\n]+")]
pub enum PolicyToken<'hdr> {
    Empty(&'hdr str),
}

pub(super) fn parse_policy<'hdr>(
    lexer: &mut Lexer<'hdr, PolicyToken<'hdr>>,
) -> Result<&'hdr str, ResultCodeError> {
    let mut res_policy: Option<&'hdr str> = None;

    let mut started = false;

    while let Some(token) = lexer.next() {
        match token {
            _ => {
                panic!(
                    "parse_policy -- Invalid token {:?} - span = {:?} - source = {:?}",
                    token,
                    lexer.span(),
                    lexer.source()
                );
            }
        }
    }

    match res_policy {
        Some(v) => Ok(v),
        None => Err(ResultCodeError::NoAssociatedPolicy),
    }
}
