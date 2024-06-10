use crate::error::AuthResultsError;

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum ReasonToken<'hdr> {
    #[regex(r#"([^"\\]|\\t|\\u|\\n|\\")*"#, |lex| lex.slice(), priority = 1)]
    MaybeReason(&'hdr str),

    #[token("\"", priority = 2)]
    DoubleQuote,
}

pub fn parse_reason<'hdr>(
    lexer: &mut Lexer<'hdr, ReasonToken<'hdr>>,
) -> Result<&'hdr str, AuthResultsError<'hdr>> {
    let mut res_reason: Option<&'hdr str> = None;

    let mut started = false;

    while let Some(token) = lexer.next() {
        match token {
            Ok(ReasonToken::MaybeReason(reason_str)) => {
                res_reason = Some(reason_str);
            }
            Ok(ReasonToken::DoubleQuote) => {
                started = match started {
                    true => break,
                    false => true,
                };
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "reason",
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

    match res_reason {
        Some(v) => Ok(v),
        None => Err(AuthResultsError::NoAssociatedReason),
    }
}
