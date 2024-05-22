//! Property types Parser

use crate::dkim::DkimProperty;

/*
use crate::auth::AuthProperty;
use crate::dmarc::DmarcProperty;
use crate;:iprev::IpRevProperty;
use crate::spf::SpfProperty;
*/

// Parse into this public type
use crate::Prop;

use super::ResultCodeError;
use super::{parse_comment, CommentToken};
use super::{parse_reason, ReasonToken};
use super::{ParseCurrentResultChoice, ParseCurrentResultCode};
use logos::{Lexer, Logos};

mod auth;

mod dkim;
use dkim::dkim_property_key::{
    parse_dkim_header_property_key, DkimHeaderPropertyKey, DkimHeaderPropertyKeyToken,
};
use dkim::dkim_property_value::{parse_dkim_header_property_value, DkimHeaderPropertyValueToken};

mod dmarc;
mod iprev;
//mod policy;
mod spf;

#[derive(Debug, Default, PartialEq)]
pub enum PropTypeKey {
    #[default]
    Nothing,
    //Auth(AuthPtype),
    DkimHeader(DkimHeaderPropertyKey),
    //Dmarc(DmarcPtype),
    //IpRev(IpRevPtype),
    //Spf(SpfPtype),
}

#[derive(Debug, Default, PartialEq)]
pub enum PtypeChoice {
    #[default]
    Nothing,
    AuthSmtp,
    DkimHeader,
    DkimPolicy, // not sure
    IpRevPolicy,
    SpfSmtp,
}

impl PtypeChoice {
    fn from_associated_method_ptype<'hdr>(
        cur_res: &'hdr Option<ParseCurrentResultChoice<'hdr>>,
        token: &'hdr PtypeToken<'hdr>,
    ) -> Self {
        match cur_res {
            Some(ParseCurrentResultChoice::Dkim(_)) => match token {
                PtypeToken::PtypeHeader => Self::DkimHeader,
                PtypeToken::PtypePolicy => Self::DkimPolicy,
                _ => Self::Nothing,
            },
            Some(ParseCurrentResultChoice::Spf(_)) => match token {
                PtypeToken::PtypeSmtp => Self::SpfSmtp,
                _ => Self::Nothing,
            },
            Some(ParseCurrentResultChoice::SmtpAuth(_)) => match token {
                PtypeToken::PtypeSmtp => Self::AuthSmtp,
                _ => Self::Nothing,
            },
            Some(ParseCurrentResultChoice::IpRev(_)) => match token {
                PtypeToken::PtypePolicy => Self::IpRevPolicy,
                _ => Self::Nothing,
            },
            _ => Self::Nothing,
        }
    }
}

#[derive(Debug, Logos)]
pub enum PtypeToken<'hdr> {
    #[token("header", priority = 1)]
    PtypeHeader,

    #[token("smtp", priority = 1)]
    PtypeSmtp,

    #[token("policy", priority = 1)]
    PtypePolicy,

    #[token("=", priority = 2)]
    Equal,

    #[token(".", priority = 2)]
    Dot,

    #[token(";", priority = 3)]
    FieldSep,

    #[token("(", priority = 3)]
    CommentStart,

    #[token("reason", priority = 5)]
    Reason,

    #[regex(r"\s+", |lex| lex.slice(), priority = 6)]
    WhiteSpaces(&'hdr str),
}

#[derive(Debug, PartialEq)]
enum PtypeStage {
    WantPtype,
    GotPtype,
    WantDot,
    WantPropertyKey,
    GotPropertyKey,
    WantReasonEq,
    WantEq,
    GotEq,
    WantPropertyVal,
    GotPropertyVal,
}

impl PtypeStage {
    fn should_ignore_whitespace(&self) -> bool {
        match self {
            _ => true,
        }
    }
}

pub fn parse_ptype_properties<'hdr>(
    lexer: &mut Lexer<'hdr, PtypeToken<'hdr>>,
    cur_res: &mut Option<ParseCurrentResultChoice<'hdr>>,
) -> Result<(), ResultCodeError> {
    let mut stage = PtypeStage::WantPtype;
    let mut cur_ptype: PtypeChoice = PtypeChoice::Nothing;
    let mut cur_property: PropTypeKey = PropTypeKey::Nothing;

    let mut cur_res_choice = match &cur_res {
        Some(choice) => choice,
        None => return Err(ResultCodeError::ParsePtypeNoMethodResult),
    };

    while let Some(token) = lexer.next() {
        match token {
            Ok(PtypeToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(comment) => {}
                    Err(e) => return Err(e),
                }
                lexer.bump(comment_lexer.span().end);
            }
            Ok(PtypeToken::PtypeSmtp | PtypeToken::PtypeHeader | PtypeToken::PtypePolicy)
                if stage == PtypeStage::WantPtype =>
            {
                let token_unwrap = token.expect("BUG: Incorrect gating.");
                let cur_ptype_try =
                    PtypeChoice::from_associated_method_ptype(cur_res, &token_unwrap);

                match cur_ptype_try {
                    PtypeChoice::Nothing => {
                        return Err(ResultCodeError::ParsePtypeBugInvalidProperty)
                    }
                    _ => {
                        cur_ptype = cur_ptype_try;
                    }
                }
                stage = PtypeStage::WantDot;
            }
            Ok(PtypeToken::Dot)
                if stage == PtypeStage::WantDot && cur_ptype != PtypeChoice::Nothing =>
            {
                cur_property = match cur_ptype {
                    PtypeChoice::DkimHeader => {
                        let mut property_key_lexer =
                            DkimHeaderPropertyKeyToken::lexer(lexer.remainder());
                        let property_key =
                            match parse_dkim_header_property_key(&mut property_key_lexer) {
                                Err(e) => return Err(e),
                                Ok(property_key) => property_key,
                            };
                        lexer.bump(property_key_lexer.span().end);
                        PropTypeKey::DkimHeader(property_key)
                    }
                    _ => return Err(ResultCodeError::PropertiesNotImplemented),
                };
                stage = PtypeStage::WantEq;
            }

            Ok(PtypeToken::FieldSep) => {
                break;
            }
            Ok(PtypeToken::WhiteSpaces(ref wsh)) if stage.should_ignore_whitespace() => {
                // cont
            }
            Ok(PtypeToken::Reason) if stage == PtypeStage::WantPtype => {
                stage = PtypeStage::WantReasonEq;
            }
            Ok(PtypeToken::Equal) if stage == PtypeStage::WantReasonEq => {
                let mut reason_lexer = ReasonToken::lexer(lexer.remainder());
                let reason_res = match parse_reason(&mut reason_lexer) {
                    Err(e) => return Err(e),
                    Ok(reason) => reason,
                };
                match cur_res {
                    Some(ref mut ref_choice) => {
                        ref_choice.set_reason(reason_res);
                    }
                    _ => {}
                }
                lexer.bump(reason_lexer.span().end);
                stage = PtypeStage::WantPtype;
            }
            Ok(PtypeToken::Equal)
                if stage == PtypeStage::WantEq && cur_property != PropTypeKey::Nothing =>
            {
                match cur_property {
                    PropTypeKey::DkimHeader(ref property) => {
                        let mut property_value_lexer =
                            DkimHeaderPropertyValueToken::lexer(lexer.remainder());
                        let property_value = match parse_dkim_header_property_value(
                            &mut property_value_lexer,
                            &property,
                            //&mut cur_res,
                        ) {
                            Err(e) => return Err(e),
                            Ok(property_value) => property_value,
                        };
                        lexer.bump(property_value_lexer.span().end);

                        match cur_res {
                            Some(ParseCurrentResultChoice::Dkim(ref mut dkim_res)) => {
                                dkim_res.set_header(&property_value);
                            }
                            _ => {}
                        }
                    }
                    _ => {
                        return Err(ResultCodeError::PropertyValuesNotImplemented);
                    }
                };
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];
                panic!(
                    "parse_ptypes_properties({:?}) -- Invalid token {:?} - span = {:?}\n - Source = {:?}\n - Clipped/span: {:?}\n - Clipped/remaining: {:?}",
                    stage,
                    token,
                    lexer.span(),
                    lexer.source(),
                    cut_span,
                    cut_slice,
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {

    use super::*;
    use insta::assert_debug_snapshot;
    use rstest::rstest;

    use crate::spf::*;

    fn prep_spf<'hdr>(s: &'hdr str) -> ParseCurrentResultCode<'hdr> {
        let mut current = ParseCurrentResultCode::default();
        let mut spf_result = SpfResult::default();
        current.result = Some(ParseCurrentResultChoice::Spf(spf_result));
        current
    }

    #[rstest]
    #[case("smtp.mailfrom=example.net", 1)]
    fn spf(#[case] prop_str: &str, #[case] expected_count: usize) {
        let mut cur_spf = prep_spf(prop_str);
        let mut lexer = PtypeToken::lexer(prop_str);

        let res = parse_ptype_properties(&mut lexer, &mut cur_spf.result).unwrap();

        assert_debug_snapshot!(cur_spf);
        //assert_eq!(expected_count, res.properties.len());
    }
}
