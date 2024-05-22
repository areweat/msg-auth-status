//! Parsing dkim property values

use crate::dkim::ptypes::DkimHeader;
use crate::dkim::*;

use super::ResultCodeError;

use super::DkimHeaderPropertyKey;
use super::{parse_comment, CommentToken};

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
pub enum DkimHeaderPropertyValueToken<'hdr> {
    #[token("(", priority = 1)]
    CommentStart,

    //    #[token(";", priority = 1)]
    //    FieldSep,

    //#[regex(r#"([^"\\]|\\t|\\u|\\n|\\")*"#, |lex| lex.slice(), priority = 1)]
    #[regex(r#"[^\s;]+"#, |lex| lex.slice(), priority = 2)]
    MaybeValue(&'hdr str),

    Dummy(&'hdr str),
}

impl<'hdr> DkimHeader<'hdr> {
    fn from_parsed(pkey: &DkimHeaderPropertyKey, val: &'hdr str) -> Self {
        match pkey {
            DkimHeaderPropertyKey::TagD => DkimHeader::D(val),
            DkimHeaderPropertyKey::TagI => DkimHeader::I(val),
            DkimHeaderPropertyKey::TagB => DkimHeader::B(val),
            DkimHeaderPropertyKey::TagA => {
                let alg = match val {
                    "rsa-sha1" => DkimAlgorithm::Rsa_Sha1,
                    "rsa-sha256" => DkimAlgorithm::Rsa_Sha256,
                    "ed25519-sha256" => DkimAlgorithm::Ed25519_Sha256,
                    _ => DkimAlgorithm::Unknown(val),
                };
                DkimHeader::A(alg)
            }
            DkimHeaderPropertyKey::TagS => DkimHeader::S(val),
            DkimHeaderPropertyKey::Rfc5322From => DkimHeader::Rfc5322From(val), // not covered
        }
    }
}

pub fn parse_dkim_header_property_value<'hdr>(
    lexer: &mut Lexer<'hdr, DkimHeaderPropertyValueToken<'hdr>>,
    property_key: &DkimHeaderPropertyKey,
) -> Result<DkimHeader<'hdr>, ResultCodeError> {
    let mut value_captured = false;
    let mut cur_res: Option<DkimHeader<'hdr>> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(DkimHeaderPropertyValueToken::MaybeValue(val)) if value_captured == false => {
                cur_res = Some(DkimHeader::from_parsed(property_key, val));
                value_captured = true;
                break;
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                panic!(
                    "parse_dkim_header_property_value -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
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

    Err(ResultCodeError::RunAwayDkimPropertyKey)
}
