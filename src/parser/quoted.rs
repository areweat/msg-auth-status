use crate::error::QuotedError;

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum QuotedToken<'hdr> {
    #[regex(r#"""#, |lex| lex.slice(), priority = 25)]
    QuotedEnd(&'hdr str),

    #[regex(r#"(\\"|[^\\"])+"#, |lex| lex.slice(), priority = 50)]
    QuotedValue(&'hdr str),
}

pub fn parse_quoted<'hdr>(
    lexer: &mut Lexer<'hdr, QuotedToken<'hdr>>,
) -> Result<&'hdr str, QuotedError<'hdr>> {
    let mut want_end = false;
    let mut ret_qval: Option<&'hdr str> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(QuotedToken::QuotedEnd(_)) if want_end => {
                if let Some(qval) = ret_qval {
                    return Ok(qval);
                } else {
                    return Err(QuotedError::Bug);
                }
            }
            Ok(QuotedToken::QuotedValue(qval)) if !want_end => {
                ret_qval = Some(qval);
                want_end = true;
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "quote",
                    span_start: lexer.span().start,
                    span_end: lexer.span().end,
                    source: lexer.source(),
                    clipped_span: cut_span,
                    clipped_remaining: cut_slice,
                };
                return Err(QuotedError::ParsingDetailed(detail));
            }
        }
    }
    Err(QuotedError::RunAway)
}

#[cfg(test)]
mod test {

    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(r#"foo""#, "foo")]
    #[case(r#"foo\"bar""#, r#"foo\"bar"#)]
    fn quoted_parse(#[case] in_quoted: &'static str, #[case] expected: &'static str) {
        let mut lexer = QuotedToken::lexer(in_quoted);
        let spec = parse_quoted(&mut lexer);
        assert_eq!(spec, Ok(expected))
    }
}
