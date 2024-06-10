//! Parsing iprev property types & values

use crate::error::AuthResultsError;

/// IANA Email Authentication Methods ptype / property Mapping stages
#[derive(Debug, PartialEq)]
pub enum IpRevPolicyPropertyKey {
    IpRev,
}

impl<'hdr> TryFrom<IpRevPolicyPropertyKeyToken<'hdr>> for IpRevPolicyPropertyKey {
    type Error = AuthResultsError<'hdr>;
    fn try_from(token: IpRevPolicyPropertyKeyToken<'hdr>) -> Result<Self, Self::Error> {
        let okk = match token {
            IpRevPolicyPropertyKeyToken::IpRev => Self::IpRev,
            _ => return Err(AuthResultsError::ParsePtypeBugInvalidProperty),
        };
        Ok(okk)
    }
}

//----------
// Parsing iprev property
//----------

use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum IpRevPolicyPropertyKeyToken<'hdr> {
    #[token("iprev", priority = 1)]
    IpRev,

    #[token("(", priority = 2)]
    CommentStart,

    #[regex(r"\s+", |lex| lex.slice(), priority = 6)]
    WhiteSpaces(&'hdr str),
}

pub fn parse_iprev_policy_property_key<'hdr>(
    lexer: &mut Lexer<'hdr, IpRevPolicyPropertyKeyToken<'hdr>>,
) -> Result<IpRevPolicyPropertyKey, AuthResultsError<'hdr>> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(IpRevPolicyPropertyKeyToken::IpRev) => {
                let property = token.map_err(|_| AuthResultsError::ParsePtypeBugPropertyGating)?;
                let mapped_property_res: Result<IpRevPolicyPropertyKey, AuthResultsError<'hdr>> =
                    property.try_into();
                let mapped_property = mapped_property_res
                    .map_err(|_| AuthResultsError::ParsePtypeBugInvalidProperty)?;
                return Ok(mapped_property);
            }
            Ok(IpRevPolicyPropertyKeyToken::WhiteSpaces(_)) => {
                // cont
            }
            Ok(IpRevPolicyPropertyKeyToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(_comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "iprev_property_key",
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
    Err(AuthResultsError::RunAwayIpRevPropertyKey)
}
