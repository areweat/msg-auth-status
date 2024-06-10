//! Property types Parser

use super::ParseCurrentResultChoice;
use super::{parse_comment, CommentToken};
use super::{parse_reason, ReasonToken};
use logos::{Lexer, Logos};

use crate::error::AuthResultsError;

// mod dmarc

//------------------------------------------------------------------------
// SMTP Auth ptypes
//------------------------------------------------------------------------

mod auth;
use auth::auth_property_key::{
    parse_auth_smtp_property_key, AuthSmtpPropertyKey, AuthSmtpPropertyKeyToken,
};
use auth::auth_property_value::{parse_auth_smtp_property_value, AuthSmtpPropertyValueToken};

//------------------------------------------------------------------------
// DKIM ptypes
//------------------------------------------------------------------------

mod dkim;
use dkim::dkim_property_key::{
    parse_dkim_header_property_key, parse_dkim_policy_property_key, DkimHeaderPropertyKey,
    DkimHeaderPropertyKeyToken, DkimPolicyPropertyKey, DkimPolicyPropertyKeyToken,
};
use dkim::dkim_property_value::{parse_dkim_header_property_value, DkimHeaderPropertyValueToken};
use dkim::dkim_property_value::{parse_dkim_policy_property_value, DkimPolicyPropertyValueToken};

//------------------------------------------------------------------------
// IpRev ptypes
//------------------------------------------------------------------------

mod iprev;
use iprev::iprev_property_key::{
    parse_iprev_policy_property_key, parse_iprev_smtp_property_key, IpRevPolicyPropertyKey,
    IpRevPolicyPropertyKeyToken, IpRevSmtpPropertyKey, IpRevSmtpPropertyKeyToken,
};
use iprev::iprev_property_value::{
    parse_iprev_policy_property_value, parse_iprev_smtp_property_value,
    IpRevPolicyPropertyValueToken, IpRevSmtpPropertyValueToken,
};

//------------------------------------------------------------------------
// SPF ptypes
//------------------------------------------------------------------------

mod spf;
use spf::spf_property_key::{
    parse_spf_smtp_property_key, SpfSmtpPropertyKey, SpfSmtpPropertyKeyToken,
};
use spf::spf_property_value::{parse_spf_smtp_property_value, SpfSmtpPropertyValueToken};

//------------------------------------------------------------------------
// Ptype Parsing
//------------------------------------------------------------------------

#[derive(Debug, Default, PartialEq)]
pub enum PropTypeKey<'hdr> {
    #[default]
    Nothing,
    AuthSmtp(AuthSmtpPropertyKey),
    DkimHeader(DkimHeaderPropertyKey<'hdr>),
    DkimPolicy(DkimPolicyPropertyKey<'hdr>),
    SpfSmtp(SpfSmtpPropertyKey),
    IpRevPolicy(IpRevPolicyPropertyKey<'hdr>),
    IpRevSmtp(IpRevSmtpPropertyKey<'hdr>),
    //Dmarc(DmarcPtype),
}

#[derive(Debug, Default, PartialEq)]
pub enum PtypeChoice {
    #[default]
    Nothing,
    AuthSmtp,
    DkimHeader,
    DkimPolicy, // not sure
    IpRevPolicy,
    IpRevSmtp, // fastmail breaks RFC
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
                PtypeToken::PtypeSmtp => Self::IpRevSmtp,
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

    #[regex(r"[\s\r\n\t]+", |lex| lex.slice(), priority = 6)]
    Whs(&'hdr str),
}

#[derive(Clone, Debug, PartialEq)]
enum WantStage {
    Ptype,
    Dot,
    ReasonEq,
    Eq,
}

impl core::fmt::Display for WantStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            WantStage::Ptype => write!(f, "Ptype"),
            WantStage::Dot => write!(f, "Dot"),
            WantStage::ReasonEq => write!(f, "ReasonEq"),
            WantStage::Eq => write!(f, "Eq"),
        }
    }
}

impl WantStage {
    fn should_ignore_whitespace(&self) -> bool {
        true
    }
}

pub fn parse_ptype_properties<'hdr>(
    lexer: &mut Lexer<'hdr, PtypeToken<'hdr>>,
    cur_res: &mut Option<ParseCurrentResultChoice<'hdr>>,
) -> Result<usize, AuthResultsError<'hdr>> {
    let mut stage = WantStage::Ptype;
    let mut cur_ptype: PtypeChoice = PtypeChoice::Nothing;
    let mut cur_property: PropTypeKey<'hdr> = PropTypeKey::Nothing;

    let mut parsed_end = lexer.span().start;
    let mut parsed_modifier = 0;

    let mut props_started = false;

    while let Some(token) = lexer.next() {
        match token {
            Ok(PtypeToken::CommentStart) => {
                props_started = true;
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                let _comment = match parse_comment(&mut comment_lexer) {
                    Ok(comment) => comment,
                    Err(e) => return Err(e),
                };
                lexer.bump(comment_lexer.span().end);
            }
            Ok(PtypeToken::PtypeSmtp | PtypeToken::PtypeHeader | PtypeToken::PtypePolicy)
                if stage == WantStage::Ptype =>
            {
                props_started = true;
                let token_unwrap = token.expect("BUG: Incorrect gating.");
                let cur_ptype_try =
                    PtypeChoice::from_associated_method_ptype(cur_res, &token_unwrap);

                match cur_ptype_try {
                    PtypeChoice::Nothing => {
                        let cut_slice = &lexer.source()[lexer.span().start..];
                        let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                        let detail = crate::error::ParsingDetail {
                            component: "parse_properties",
                            span_start: lexer.span().start,
                            span_end: lexer.span().end,
                            source: lexer.source(),
                            clipped_span: cut_span,
                            clipped_remaining: cut_slice,
                        };
                        return Err(AuthResultsError::ParsePtypeInvalidAssociatedPtype(detail));
                    }
                    _ => {
                        cur_ptype = cur_ptype_try;
                    }
                }
                stage = WantStage::Dot;
            }
            Ok(PtypeToken::Dot) if stage == WantStage::Dot && cur_ptype != PtypeChoice::Nothing => {
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
                    PtypeChoice::DkimPolicy => {
                        let mut property_key_lexer =
                            DkimPolicyPropertyKeyToken::lexer(lexer.remainder());
                        let property_key =
                            match parse_dkim_policy_property_key(&mut property_key_lexer) {
                                Err(e) => return Err(e),
                                Ok(property_key) => property_key,
                            };
                        lexer.bump(property_key_lexer.span().end);
                        PropTypeKey::DkimPolicy(property_key)
                    }
                    PtypeChoice::IpRevPolicy => {
                        let mut property_key_lexer =
                            IpRevPolicyPropertyKeyToken::lexer(lexer.remainder());
                        let property_key =
                            match parse_iprev_policy_property_key(&mut property_key_lexer) {
                                Err(e) => return Err(e),
                                Ok(property_key) => property_key,
                            };
                        lexer.bump(property_key_lexer.span().end);
                        PropTypeKey::IpRevPolicy(property_key)
                    }
                    PtypeChoice::IpRevSmtp => {
                        let mut property_key_lexer =
                            IpRevSmtpPropertyKeyToken::lexer(lexer.remainder());
                        let property_key =
                            match parse_iprev_smtp_property_key(&mut property_key_lexer) {
                                Err(e) => return Err(e),
                                Ok(property_key) => property_key,
                            };
                        lexer.bump(property_key_lexer.span().end);
                        PropTypeKey::IpRevSmtp(property_key)
                    }
                    PtypeChoice::SpfSmtp => {
                        let mut property_key_lexer =
                            SpfSmtpPropertyKeyToken::lexer(lexer.remainder());
                        let property_key =
                            match parse_spf_smtp_property_key(&mut property_key_lexer) {
                                Err(e) => return Err(e),
                                Ok(property_key) => property_key,
                            };
                        lexer.bump(property_key_lexer.span().end);
                        PropTypeKey::SpfSmtp(property_key)
                    }
                    PtypeChoice::AuthSmtp => {
                        let mut property_key_lexer =
                            AuthSmtpPropertyKeyToken::lexer(lexer.remainder());
                        let property_key =
                            match parse_auth_smtp_property_key(&mut property_key_lexer) {
                                Err(e) => return Err(e),
                                Ok(property_key) => property_key,
                            };
                        lexer.bump(property_key_lexer.span().end);
                        PropTypeKey::AuthSmtp(property_key)
                    }
                    _ => return Err(AuthResultsError::PropertiesNotImplemented),
                };
                stage = WantStage::Eq;
            }

            Ok(PtypeToken::FieldSep) => {
                if props_started {
                    parsed_modifier += 1;
                }
                break;
            }
            Ok(PtypeToken::Whs(_)) if stage.should_ignore_whitespace() => {
                // cont
            }
            Ok(PtypeToken::Reason) if stage == WantStage::Ptype => {
                props_started = true;
                stage = WantStage::ReasonEq;
            }
            Ok(PtypeToken::Equal) if stage == WantStage::ReasonEq => {
                let mut reason_lexer = ReasonToken::lexer(lexer.remainder());
                let reason_res = match parse_reason(&mut reason_lexer) {
                    Err(e) => return Err(e),
                    Ok(reason) => reason,
                };
                if let Some(ref mut ref_choice) = cur_res {
                    ref_choice.set_reason(reason_res);
                }
                lexer.bump(reason_lexer.span().end);
                stage = WantStage::Ptype;
            }
            Ok(PtypeToken::Equal)
                if stage == WantStage::Eq && cur_property != PropTypeKey::Nothing =>
            {
                match cur_property {
                    PropTypeKey::DkimHeader(ref property) => {
                        let mut property_value_lexer =
                            DkimHeaderPropertyValueToken::lexer(lexer.remainder());
                        let property_value = match parse_dkim_header_property_value(
                            &mut property_value_lexer,
                            property,
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
                    PropTypeKey::DkimPolicy(ref property) => {
                        let mut property_value_lexer =
                            DkimPolicyPropertyValueToken::lexer(lexer.remainder());
                        let property_value = match parse_dkim_policy_property_value(
                            &mut property_value_lexer,
                            property,
                        ) {
                            Err(e) => return Err(e),
                            Ok(property_value) => property_value,
                        };
                        lexer.bump(property_value_lexer.span().end);

                        match cur_res {
                            Some(ParseCurrentResultChoice::Dkim(ref mut dkim_res)) => {
                                dkim_res.set_policy(&property_value);
                            }
                            _ => {}
                        }
                    }
                    PropTypeKey::IpRevPolicy(ref property) => {
                        let mut property_value_lexer =
                            IpRevPolicyPropertyValueToken::lexer(lexer.remainder());
                        let property_value = match parse_iprev_policy_property_value(
                            &mut property_value_lexer,
                            property,
                        ) {
                            Err(e) => return Err(e),
                            Ok(property_value) => property_value,
                        };
                        lexer.bump(property_value_lexer.span().end);

                        match cur_res {
                            Some(ParseCurrentResultChoice::IpRev(ref mut iprev_res)) => {
                                iprev_res.set_policy(&property_value);
                            }
                            _ => {}
                        }
                    }
                    PropTypeKey::IpRevSmtp(ref property) => {
                        let mut property_value_lexer =
                            IpRevSmtpPropertyValueToken::lexer(lexer.remainder());
                        let property_value = match parse_iprev_smtp_property_value(
                            &mut property_value_lexer,
                            property,
                        ) {
                            Err(e) => return Err(e),
                            Ok(property_value) => property_value,
                        };
                        lexer.bump(property_value_lexer.span().end);

                        match cur_res {
                            Some(ParseCurrentResultChoice::IpRev(ref mut iprev_res)) => {
                                iprev_res.set_smtp(&property_value);
                            }
                            _ => {}
                        }
                    }
                    PropTypeKey::SpfSmtp(ref property) => {
                        let mut property_value_lexer =
                            SpfSmtpPropertyValueToken::lexer(lexer.remainder());
                        let property_value = match parse_spf_smtp_property_value(
                            &mut property_value_lexer,
                            property,
                        ) {
                            Err(e) => return Err(e),
                            Ok(property_value) => property_value,
                        };
                        lexer.bump(property_value_lexer.span().end);

                        match cur_res {
                            Some(ParseCurrentResultChoice::Spf(ref mut spf_res)) => {
                                spf_res.set_smtp(&property_value);
                            }
                            _ => {}
                        }
                    }
                    PropTypeKey::AuthSmtp(ref property) => {
                        let mut property_value_lexer =
                            AuthSmtpPropertyValueToken::lexer(lexer.remainder());
                        let property_value = match parse_auth_smtp_property_value(
                            &mut property_value_lexer,
                            property,
                        ) {
                            Err(e) => return Err(e),
                            Ok(property_value) => property_value,
                        };
                        lexer.bump(property_value_lexer.span().end);

                        match cur_res {
                            Some(ParseCurrentResultChoice::SmtpAuth(ref mut auth_res)) => {
                                auth_res.set_smtp(&property_value);
                            }
                            _ => {}
                        }
                    }
                    _ => {
                        return Err(AuthResultsError::PropertyValuesNotImplemented);
                    }
                };
                stage = WantStage::Ptype;
            }
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];

                let detail = crate::error::ParsingDetail {
                    component: "parse_ptypes_properties",
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

    if props_started {
        parsed_end = lexer.span().end - parsed_modifier;
    }

    Ok(parsed_end)
}

#[cfg(test)]
mod test {

    use super::*;
    use insta::assert_debug_snapshot;
    use rstest::rstest;

    use crate::parser::auth_results::ParseCurrentResultCode;
    use crate::spf::*;

    fn prep_spf<'hdr>() -> ParseCurrentResultCode<'hdr> {
        let mut current = ParseCurrentResultCode::default();
        let spf_result = SpfResult::default();
        current.result = Some(ParseCurrentResultChoice::Spf(spf_result));
        current
    }

    #[rstest]
    #[case("smtp.mailfrom=example.net")]
    fn spf(#[case] prop_str: &str) {
        let mut cur_spf = prep_spf();
        let mut lexer = PtypeToken::lexer(prop_str);

        let _res = parse_ptype_properties(&mut lexer, &mut cur_spf.result).unwrap();

        assert_debug_snapshot!(cur_spf);
    }
}
