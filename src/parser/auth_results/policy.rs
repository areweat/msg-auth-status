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

use crate::error::AuthResultsError;

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
#[logos(skip r"[ \r\n]+")]
pub enum PolicyToken<'hdr> {
    // TODO
    #[allow(dead_code)]
    Empty(&'hdr str),
}

pub fn parse_policy<'hdr>(
    _lexer: &mut Lexer<'hdr, PolicyToken<'hdr>>,
) -> Result<&'hdr str, AuthResultsError<'hdr>> {
    let res_policy: Option<&'hdr str> = None;

    /*
    while let Some(token) = lexer.next() {
        match token {
    _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail { component: "parse_ptypes_properties",
                                                           span_start: lexer.span().start, span_end: lexer.span().end,
                                                           source: lexer.source(), clipped_span: cut_span, clipped_remaining: cut_slice };
                return Err(AuthResultsError::ParsingDetailed(detail));

            }
        }
    } */

    match res_policy {
        Some(v) => Ok(v),
        None => Err(AuthResultsError::NoAssociatedPolicy),
    }
}
