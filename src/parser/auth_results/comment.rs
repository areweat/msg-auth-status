use super::ResultCodeError;

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
) -> Result<(), ResultCodeError> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(CommentToken::Comment(comment)) => {
                // ignore
            }
            Ok(CommentToken::CommentEnd) => {
                return Ok(());
            }
            _ => {
                panic!(
                    "parse_comment -- Invalid token {:?} - span = {:?} - source = {:?}",
                    token,
                    lexer.span(),
                    lexer.source()
                );
            }
        }
    }
    Err(ResultCodeError::RunAwayComment)
}
