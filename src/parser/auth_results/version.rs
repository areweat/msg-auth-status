use super::{parse_comment, CommentToken};

use crate::error::AuthResultsError;
use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
#[logos(skip r"[ ]+")]
pub enum VersionToken<'hdr> {
    #[regex(r"[0-9]+", |lex| lex.slice(), priority = 1)]
    MaybeVersion(&'hdr str),

    #[token("(", priority = 2)]
    CommentStart,

    #[token("=", priority = 3)]
    Equal,
}

pub fn parse_version<'hdr>(
    lexer: &mut Lexer<'hdr, VersionToken<'hdr>>,
) -> Result<u32, AuthResultsError<'hdr>> {
    let mut res_version: Option<u32> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(VersionToken::MaybeVersion(version_str)) => {
                let version_u32: u32 = version_str
                    .parse()
                    .map_err(|_| AuthResultsError::InvalidVersion)?;
                res_version = Some(version_u32);
            }
            Ok(VersionToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(_comment) => {}
                    Err(e) => return Err(e),
                }
                *lexer = VersionToken::lexer(comment_lexer.remainder());
            }
            Ok(VersionToken::Equal) => {
                break;
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "version",
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
    match res_version {
        Some(v) => Ok(v),
        None => Err(AuthResultsError::NoAssociatedVersion),
    }
}
