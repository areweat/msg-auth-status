//! Parsing iprev property types & values
//! https://www.iana.org/assignments/email-auth/email-auth.xhtml

use crate::iprev::*;

use super::ResultCodeError;

/// IANA Email Authentication Methods ptype / property Mapping stages
#[derive(Debug, PartialEq)]
pub enum IpRevPolicyPropertyKey {
    IpRev,
}

impl<'hdr> TryFrom<IpRevPolicyPropertyKeyToken<'hdr>> for IpRevPolicyPropertyKey {
    type Error = ResultCodeError;
    fn try_from(token: IpRevPolicyPropertyKeyToken<'hdr>) -> Result<Self, Self::Error> {
        let okk = match token {
            IpRevPolicyPropertyKeyToken::IpRev => Self::IpRev,
            _ => return Err(ResultCodeError::ParsePtypeBugInvalidProperty),
        };
        Ok(okk)
    }
}

//----------
// Parsing iprev property
// https://www.iana.org/assignments/email-auth/email-auth.xhtml
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
) -> Result<IpRevPolicyPropertyKey, ResultCodeError> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(IpRevPolicyPropertyKeyToken::IpRev) => {
                let property = token.map_err(|_| ResultCodeError::ParsePtypeBugPropertyGating)?;
                let mapped_property_res: Result<IpRevPolicyPropertyKey, ResultCodeError> =
                    property.try_into();
                let mapped_property = mapped_property_res
                    .map_err(|_| ResultCodeError::ParsePtypeBugInvalidProperty)?;
                return Ok(mapped_property);
            }
            Ok(IpRevPolicyPropertyKeyToken::WhiteSpaces(_)) => {
                // cont
            }
            Ok(IpRevPolicyPropertyKeyToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
                //*lexer = X::lexer(comment_lexer.remainder());
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                panic!(
                    "parse_iprev_property_key -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
                    token,
                    lexer.span(),
                    lexer.source(),
                    cut_span,
	                cut_slice,
                );
            }
        }
    }
    Err(ResultCodeError::RunAwayIpRevPropertyKey)
}
