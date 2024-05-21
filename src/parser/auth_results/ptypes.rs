//! Property types

mod auth;
mod dkim;
mod dmarc;
mod iprev;
//mod policy;
mod spf;

pub use auth::{AuthProperty, AuthPtype};
pub use dkim::{DkimProperty, DkimPropertyKey};
pub use dmarc::{DmarcProperty, DmarcPtype};
pub use iprev::{IpRevProperty, IpRevPtype};
pub use spf::{SpfProperty, SpfPtype};

#[derive(Debug)]
pub enum PropType<'hdr> {
    Auth(AuthProperty<'hdr>),
    Dkim(DkimProperty<'hdr>),
    Dmarc(DmarcProperty<'hdr>),
    IpRev(IpRevProperty<'hdr>),
    Spf(SpfProperty<'hdr>),
    Unknown(UnknownProperty<'hdr>),
}

#[derive(Debug)]
pub enum PropTypeKey {
    Auth(AuthPtype),
    Dkim(DkimPtype),
    Dmarc(DmarcPtype),
    IpRev(IpRevPtype),
    Spf(SpfPtype),
}

#[derive(Debug)]
pub struct UnknownProperty<'hdr> {
    ptype: &'hdr str,
    pval: &'hdr str,
}

//--------------------------------
// Parser
//--------------------------------

use super::ResultCodeError;
use super::{parse_comment, CommentToken};
use super::{parse_reason, ReasonToken};
use super::{ParseCurrentResultChoice, ParseCurrentResultCode};
use logos::{Lexer, Logos};

use dkim::{parse_dkim_property_key, DkimPropertyToken};

#[derive(Debug, Default)]
pub enum PtypeChoice {
    #[default]
    Nothing,
    Header,
    Smtp,
    Policy,
}

impl TryFrom<PtypeToken<'_>> for PtypeChoice {
    type Error = ResultCodeError;
    fn try_from(token: PtypeToken<'_>) -> Result<Self, Self::Error> {
        match token {
            PtypeToken::PtypeHeader => Ok(Self::Header),
            PtypeToken::PtypeSmtp => Ok(Self::Smtp),
            PtypeToken::PtypePolicy => Ok(Self::Policy),
            _ => Err(ResultCodeError::ParsePtypeBugGating),
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

    //#[token("body", priority = 3)]
    //PtypeBody, // TODO: smime

    //#[token("dns", priority = 3)]
    //PtypeDns, // TODO: dnswl
    #[token(";", priority = 3)]
    FieldSep,

    #[token("(", priority = 3)]
    CommentStart,

    // Properties
    #[token("auth", priority = 4)]
    Auth,

    #[token("mailfrom", priority = 4)]
    MailFrom,

    #[token("from", priority = 4)]
    From,

    #[token("dmarc", priority = 4)]
    Dmarc,

    #[token("iprev", priority = 4)]
    IpRev,

    #[token("helo", priority = 4)]
    Helo,

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
    fn should_ignore_whitespace(&self) -> bool{
        match self {
            // TODO value parsing
            _ => true,
        }
    }
}

pub fn parse_ptype_properties<'hdr>(
    lexer: &mut Lexer<'hdr, PtypeToken<'hdr>>,
    cur_res: &mut ParseCurrentResultCode<'hdr>,
) -> Result<u32, ResultCodeError> {
    let mut properties_count = 0;
    let mut stage = PtypeStage::WantPtype;
    let mut cur_ptype: PtypeChoice = PtypeChoice::Nothing;
    
    while let Some(token) = lexer.next() {
        match token {
            Ok(PtypeToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(comment) => {}
                    Err(e) => return Err(e),
                }
                *lexer = PtypeToken::lexer(comment_lexer.remainder());
            },
            Ok(PtypeToken::PtypeSmtp | PtypeToken::PtypeHeader | PtypeToken::PtypePolicy) if stage == PtypeStage::WantPtype => {
                let cur_ptype_try: Result<PtypeChoice, ResultCodeError> = token
                    .expect("Was already unwrapped Ok - this would be bad Bug.")
                    .try_into();
                
                match cur_ptype_try {
                    Err(_) => return Err(ResultCodeError::ParsePtypeBugInvalidProperty),
                    Ok(choice) => {
                        cur_ptype = choice;
                    },
                }
                stage = PtypeStage::WantDot;
            },
            Ok(PtypeToken::Dot) if stage == PtypeStage::WantDot => {
                stage = PtypeStage::WantPropertyKey;
            }
            
            Ok(PtypeToken::FieldSep) => {
                break;
            },
            Ok(PtypeToken::WhiteSpaces(ref wsh)) if stage.should_ignore_whitespace() => {
                // cont
            },
            Ok(PtypeToken::Reason) if stage == PtypeStage::WantPtype => {
                stage = PtypeStage::WantReasonEq;
            },
            Ok(PtypeToken::Equal) if stage == PtypeStage::WantReasonEq => {
                let mut reason_lexer = ReasonToken::lexer(lexer.remainder());                
                let reason_res = match parse_reason(&mut reason_lexer) {
			        Err(e) => return Err(e),
                    Ok(reason) => reason,
                };
                *lexer = PtypeToken::lexer(reason_lexer.remainder());                
                stage = PtypeStage::WantPtype;                
            },
            Ok(PtypeToken::Equal) if stage == PtypeStage::WantEq => {
                stage = PtypeStage::WantPropertyVal;
            },
            _ => {
                let cut_slice = &lexer.source()[lexer.span().start..];
                let cut_span = &lexer.source()[lexer.span().start .. lexer.span().end];                
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
    Ok(properties_count)
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
    fn spf(#[case] prop_str: &str, #[case] expected_count: u32) {
        let mut cur_spf = prep_spf(prop_str);
        let mut lexer = PtypeToken::lexer(prop_str);

        let count = parse_ptype_properties(&mut lexer, &mut cur_spf).unwrap();

        assert_debug_snapshot!(cur_spf);
        assert_eq!(expected_count, count);
    }
}
