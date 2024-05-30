//! Parsing iprev property values

use crate::iprev::ptypes::IpRevPolicy;
use crate::iprev::*;

use super::ResultCodeError;

use super::IpRevPolicyPropertyKey;
use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum IpRevPolicyPropertyValueToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    #[regex(r#"[^\s;]+"#, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),

    Dummy(&'hdr str),
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
) -> Result<IpRevPolicy<'hdr>, ResultCodeError> {
    let mut value_captured = false;
    let mut cur_res: Option<IpRevPolicy<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(IpRevPolicyPropertyValueToken::MaybeValue(val)) if value_captured == false => {
                cur_res = Some(IpRevPolicy::from_parsed(property_key, val));
                value_captured = true;
                break;
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

    Err(ResultCodeError::RunAwayIpRevPropertyValue)
}
