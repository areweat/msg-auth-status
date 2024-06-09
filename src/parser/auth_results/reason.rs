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
) -> Result<&'hdr str, AuthResultsError> {
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
                panic!(
                    "parse_reason -- Invalid token {:?} - span = {:?} - source = {:?}",
                    token,
                    lexer.span(),
                    lexer.source()
                );
            }
        }
    }

    match res_reason {
        Some(v) => Ok(v),
        None => Err(AuthResultsError::NoAssociatedReason),
    }
}
