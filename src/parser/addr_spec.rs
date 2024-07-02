//! RFC 8222 addr-spec
//!
//! This is required for the verifier

use super::comment::{parse_comment, CommentToken};
use super::quoted::{parse_quoted, QuotedToken};
use crate::addr::AddrSpec;
use crate::error::AddrSpecError;
use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum AddrSpecToken<'hdr> {
    #[token("(", priority = 100)]
    CommentStart,

    #[token("<", priority = 100)]
    Lt,

    #[token(">", priority = 100)]
    Gt,

    #[regex("@", priority = 100)]
    At,

    #[token(r##"""##, priority = 100)]
    DoubleQuoteStart,

    #[regex(r##"[\r\n\t ]+"##, |lex| lex.slice(), priority = 50)]
    Fws(&'hdr str),

    #[regex(r##"[^""><(@\r\n\t ]+"##, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),
}

#[derive(Debug, Default, PartialEq)]
struct ParsingProgress<'hdr> {
    display_name: Option<&'hdr str>,
    local_part: Option<&'hdr str>,
    domain: Option<&'hdr str>,
    raw: Option<&'hdr str>,
}

impl<'hdr> TryFrom<ParsingProgress<'hdr>> for AddrSpec<'hdr> {
    type Error = AddrSpecError<'hdr>;
    fn try_from(try_spec: ParsingProgress<'hdr>) -> Result<Self, Self::Error> {
        let raw = match try_spec.raw {
            Some(raw) => raw,
            None => return Err(AddrSpecError::NoAssociatedAddrSpec),
        };
        let local_part = match try_spec.local_part {
            Some(local_part) => local_part,
            None => return Err(AddrSpecError::NoAssociatedLocalPart),
        };
        let domain = match try_spec.domain {
            Some(domain) => domain,
            None => return Err(AddrSpecError::NoAssociatedDomain),
        };
        Ok(AddrSpec {
            raw,
            display_name: try_spec.display_name,
            local_part,
            domain,
        })
    }
}

#[derive(Debug, PartialEq)]
enum WhereAt {
    WantLtStart,
    WantLocalPart,
    WantAt,
    WantDomain,
    GotDomain,
}

impl From<WhereAt> for &'static str {
    fn from(w: WhereAt) -> &'static str {
        match w {
            WhereAt::WantLtStart => "WantLtStart",
            WhereAt::WantLocalPart => "WantLocalPart",
            WhereAt::WantAt => "WantAt",
            WhereAt::WantDomain => "WantDomain",
            WhereAt::GotDomain => "GotDomain",
        }
    }
}

pub fn parse_addr_spec<'hdr>(
    lexer: &mut Lexer<'hdr, AddrSpecToken<'hdr>>,
    disable_lt_end_gt: bool,
) -> Result<AddrSpec<'hdr>, AddrSpecError<'hdr>> {
    let mut stage = match disable_lt_end_gt {
        false => WhereAt::WantLtStart,
        true => WhereAt::WantLocalPart,
    };
    let mut progress = ParsingProgress::default();

    let start = lexer.span().start;

    while let Some(token) = lexer.next() {
        match token {
            Ok(AddrSpecToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(_comment) => {}
                    Err(e) => return Err(AddrSpecError::ParseComment(e)),
                }
                *lexer = AddrSpecToken::lexer(comment_lexer.remainder());
            }
            Ok(AddrSpecToken::Fws(_)) if stage == WhereAt::WantLtStart => {
                // cont.
            }
            Ok(AddrSpecToken::DoubleQuoteStart)
                if !disable_lt_end_gt && stage == WhereAt::WantLtStart =>
            {
                let mut display_name_lexer = QuotedToken::lexer(lexer.remainder());
                progress.display_name = match parse_quoted(&mut display_name_lexer) {
                    Ok(display_name) => Some(display_name),
                    Err(e) => return Err(AddrSpecError::ParseDisplayName(e)),
                };
                lexer.bump(display_name_lexer.span().end);
            }
            Ok(AddrSpecToken::Lt) if !disable_lt_end_gt && stage == WhereAt::WantLtStart => {
                stage = WhereAt::WantLocalPart;
            }
            Ok(AddrSpecToken::Gt) if !disable_lt_end_gt && stage == WhereAt::GotDomain => {
                progress.raw = Some(&lexer.source()[start..lexer.span().end]);
                break;
            }
            Ok(AddrSpecToken::At) if stage == WhereAt::WantAt => {
                stage = WhereAt::WantDomain;
            }
            Ok(AddrSpecToken::MaybeValue(val)) if stage == WhereAt::WantLocalPart => {
                progress.local_part = Some(val);
                stage = WhereAt::WantAt;
            }
            Ok(AddrSpecToken::MaybeValue(val)) if stage == WhereAt::WantDomain => {
                progress.domain = Some(val);
                stage = match disable_lt_end_gt {
                    false => WhereAt::GotDomain,
                    true => {
                        progress.raw = Some(&lexer.source()[start..lexer.span().end]);
                        break;
                    }
                };
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: stage.into(),
                    span_start: lexer.span().start,
                    span_end: lexer.span().end,
                    source: lexer.source(),
                    clipped_span: cut_span,
                    clipped_remaining: cut_slice,
                };
                return Err(AddrSpecError::ParsingDetailed(detail));
            }
        }
    }

    progress.try_into()
}

#[cfg(test)]
mod test {

    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("<foo@bar.com>", AddrSpec { display_name: None, local_part: "foo", domain: "bar.com", raw: "<foo@bar.com>" } )]
    #[case("<foo+mailbox@bar.com>", AddrSpec { display_name: None, local_part: "foo+mailbox", domain: "bar.com", raw: "<foo+mailbox@bar.com>" } )]
    #[case(r#""meow" <foo@bar.com>"#, AddrSpec { display_name: Some("meow"), local_part: "foo", domain: "bar.com", raw: r#""meow" <foo@bar.com>"# } )]
    fn addr_parse(#[case] in_hdr: &'static str, #[case] expected: AddrSpec<'static>) {
        let mut lexer = AddrSpecToken::lexer(in_hdr);
        let spec = parse_addr_spec(&mut lexer, false);
        assert_eq!(spec, Ok(expected))
    }
}
