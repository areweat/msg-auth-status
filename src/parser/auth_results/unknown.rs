//! Unknown non-supported methods parsing with the goal just not erroring but finding the end for the raw unparsed form until ;
//!
//! Note unknown property types are elsewhere - this is only for the unknown methods that are not supported

use logos::{Lexer, Logos};

use super::{parse_comment, CommentToken};

use crate::parser::auth_results::AuthResultsError;

#[derive(Debug, Logos)]
pub enum UnknownToken<'hdr> {
    #[token("(")]
    CommentStart,

    #[token(";")]
    FieldSep,

    #[regex(r"[^(;]+", |lex| lex.slice())]
    EverythingElse(&'hdr str),
}

pub fn parse_unknown<'hdr>(
    lexer: &mut Lexer<'hdr, UnknownToken<'hdr>>,
) -> Result<usize, AuthResultsError<'hdr>> {
    let mut res_end: Option<usize> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(UnknownToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                let _comment = match parse_comment(&mut comment_lexer) {
                    Ok(comment) => comment,
                    Err(e) => return Err(AuthResultsError::ParseComment(e)),
                };
                lexer.bump(comment_lexer.span().end);
                res_end = Some(lexer.span().end);
            }
            Ok(UnknownToken::FieldSep) => {
                res_end = Some(lexer.span().end - 1);
                break;
            }
            Ok(UnknownToken::EverythingElse(_)) => {
                res_end = Some(lexer.span().end);
                // cont
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "parse_unknown",
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

    match res_end {
        Some(v) => Ok(v),
        None => Err(AuthResultsError::RunawayUnknownMethod(lexer.span().start)),
    }
}
