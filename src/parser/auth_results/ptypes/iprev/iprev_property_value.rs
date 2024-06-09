//! Parsing iprev property values

use super::IpRevPolicyPropertyKey;
use super::{parse_comment, CommentToken};

use crate::error::AuthResultsError;
use crate::iprev::ptypes::IpRevPolicy;

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum IpRevPolicyPropertyValueToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    #[regex(r#"[^(\s\r\n\t;]+"#, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),

    #[regex(r"[\s\r\n\t]+", |lex| lex.slice(), priority = 3)]
    Whs(&'hdr str),
}

impl<'hdr> IpRevPolicy<'hdr> {
    fn from_parsed(pkey: &IpRevPolicyPropertyKey, val: &'hdr str) -> Self {
        match pkey {
            IpRevPolicyPropertyKey::IpRev => IpRevPolicy::IpRev(val),
        }
    }
}

pub fn parse_iprev_policy_property_value<'hdr>(
    lexer: &mut Lexer<'hdr, IpRevPolicyPropertyValueToken<'hdr>>,
    property_key: &IpRevPolicyPropertyKey,
) -> Result<IpRevPolicy<'hdr>, AuthResultsError> {
    let mut cur_res: Option<IpRevPolicy<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(IpRevPolicyPropertyValueToken::MaybeValue(val)) => {
                cur_res = Some(IpRevPolicy::from_parsed(property_key, val));
                break;
            }
            Ok(IpRevPolicyPropertyValueToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(_comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
            }
            Ok(IpRevPolicyPropertyValueToken::Whs(_)) => {
                // cont
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                panic!(
                    "parse_iprev_policy_property_value -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
                    token,
                    lexer.span(),
                    lexer.source(),
                    cut_span,
	                cut_slice,
                );
            }
        }
    }

    if let Some(value) = cur_res {
        return Ok(value);
    }

    Err(AuthResultsError::RunAwayIpRevPropertyValue)
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_comment() {
        let mut lexer = IpRevPolicyPropertyValueToken::lexer("(foobar) value.foo");
        let res = parse_iprev_policy_property_value(&mut lexer, &IpRevPolicyPropertyKey::IpRev);

        assert_eq!(res, Ok(IpRevPolicy::IpRev("value.foo")));
    }
}
