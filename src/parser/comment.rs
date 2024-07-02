use crate::error::CommentError;

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum CommentToken<'hdr> {
    #[token(")", priority = 1)]
    CommentEnd,

    #[regex("[^)]+", |lex| lex.slice(), priority = 2)]
    Comment(&'hdr str),
}

pub fn parse_comment<'hdr>(
    lexer: &mut Lexer<'hdr, CommentToken<'hdr>>,
) -> Result<Option<&'hdr str>, CommentError<'hdr>> {
    let mut ret_comment: Option<&'hdr str> = None;
    while let Some(token) = lexer.next() {
        match token {
            Ok(CommentToken::Comment(comment)) => {
                ret_comment = Some(comment);
                // ignore
            }
            Ok(CommentToken::CommentEnd) => {
                return Ok(ret_comment);
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "comment",
                    span_start: lexer.span().start,
                    span_end: lexer.span().end,
                    source: lexer.source(),
                    clipped_span: cut_span,
                    clipped_remaining: cut_slice,
                };
                return Err(CommentError::ParsingDetailed(detail));
            }
        }
    }
    Err(CommentError::RunAway)
}
