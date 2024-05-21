//! Parsing for Auth Results using Logos

//use core::str::FromStr;
use logos::{Lexer, Logos};
//use strum_macros::{Display as StrumDisplay, EnumString};

use crate::auth::{SmtpAuthResult, SmtpAuthResultCode};
use crate::dkim::{DkimResult, DkimResultCode};
use crate::iprev::{IpRevResult, IpRevResultCode};
use crate::spf::{SpfResult, SpfResultCode};
use crate::AuthenticationResults;

mod comment;
mod host_version;
mod policy;
mod ptypes;
mod reason;
mod version;

use comment::{parse_comment, CommentToken};
use host_version::{parse_host_version, HostVersionToken};
use policy::{parse_policy, PolicyToken};
use ptypes::{parse_ptype_properties, PtypeToken};
use reason::{parse_reason, ReasonToken};
use version::{parse_version, VersionToken};

use ptypes::{PropType, PropTypeKey};

#[cfg(feature = "mail_parse")]
use mail_parser::HeaderValue;

#[derive(Debug)]
pub enum ResultCodeError {
    Parse,
    ParseHost(String),
    ParsePtypeBugGating,
    ParsePtypeBugInvalidProperty,
    ParsePtypeBugPropertyGating,
    InvalidDkimResult(String),
    InvalidSpfResult(String),
    InvalidIpRevResult(String),
    /// Was not a valid ptype/property per IANA and strict validation was used
    InvalidProperty,
    InvalidSmtpAuthResult(String),
    InvalidResultStage(Stage),
    InvalidVersion,
    NoAssociatedVersion,
    NoAssociatedPolicy,
    NoAssociatedReason,
    NoHostname,
    RunAwayComment,
    RunAwayDkimPropertyKey,    
    UnexpectedForwardSlash,
}

impl TryFrom<AuthResultToken<'_>> for SmtpAuthResultCode {
    type Error = ResultCodeError;

    fn try_from(token: AuthResultToken<'_>) -> Result<Self, Self::Error> {
        let res = match token {
            AuthResultToken::NoneNone => Self::NoneSmtp,
            AuthResultToken::Pass => Self::Pass,
            AuthResultToken::Fail => Self::Fail,
            AuthResultToken::TempError => Self::TempError,
            AuthResultToken::PermError => Self::PermError,
            _ => return Err(ResultCodeError::InvalidSmtpAuthResult("".to_string())),
        };
        Ok(res)
    }
}

impl TryFrom<AuthResultToken<'_>> for DkimResultCode {
    type Error = ResultCodeError;

    fn try_from(token: AuthResultToken<'_>) -> Result<Self, Self::Error> {
        let res = match token {
            AuthResultToken::NoneNone => Self::NoneDkim,
            AuthResultToken::Pass => Self::Pass,
            AuthResultToken::Fail => Self::Fail,
            AuthResultToken::Policy => Self::Policy,
            AuthResultToken::Neutral => Self::Neutral,
            AuthResultToken::TempError => Self::TempError,
            AuthResultToken::PermError => Self::PermError,
            _ => return Err(ResultCodeError::InvalidDkimResult("".to_string())),
        };
        Ok(res)
    }
}

impl TryFrom<AuthResultToken<'_>> for SpfResultCode {
    type Error = ResultCodeError;

    fn try_from(token: AuthResultToken<'_>) -> Result<Self, Self::Error> {
        let res = match token {
            AuthResultToken::NoneNone => Self::NoneSpf,
            AuthResultToken::Pass => Self::Pass,
            AuthResultToken::Fail => Self::Fail,
            AuthResultToken::SoftFail => Self::SoftFail,
            AuthResultToken::Policy => Self::Policy,
            AuthResultToken::Neutral => Self::Neutral,
            AuthResultToken::TempError => Self::TempError,
            AuthResultToken::PermError => Self::PermError,
            _ => return Err(ResultCodeError::InvalidSpfResult("".to_string())),
        };
        Ok(res)
    }
}

impl TryFrom<AuthResultToken<'_>> for IpRevResultCode {
    type Error = ResultCodeError;

    fn try_from(token: AuthResultToken<'_>) -> Result<Self, Self::Error> {
        let res = match token {
            AuthResultToken::Pass => Self::Pass,
            AuthResultToken::Fail => Self::Fail,
            AuthResultToken::TempError => Self::TempError,
            AuthResultToken::PermError => Self::PermError,
            _ => return Err(ResultCodeError::InvalidIpRevResult("".to_string())),
        };
        Ok(res)
    }
}

#[derive(Debug, Logos)]
#[logos(skip r"[ \r\n]+")]
pub enum AuthResultToken<'hdr> {
    #[token("auth", priority = 1)]
    Auth,
    #[token("dkim", priority = 1)]
    Dkim,
    #[token("spf", priority = 1)]
    Spf,
    #[token("iprev", priority = 1)]
    IpRev,

    #[token("/", priority = 1)]
    ForwardSlash,

    #[token("=", priority = 1)]
    Equal,

    #[token("none", priority = 1)]
    NoneNone,
    #[token("softfail", priority = 1)]
    SoftFail,
    #[token("fail", priority = 1)]
    Fail,
    #[token("neutral", priority = 1)]
    Neutral,
    #[token("pass", priority = 1)]
    Pass,
    #[token("temperror", priority = 1)]
    TempError,
    #[token("permerror", priority = 2)]
    PermError,

    #[token("reason", priority = 2)]
    Reason,

    #[token("policy", priority = 3)]
    Policy,

    #[token(";", priority = 5)]
    FieldSeparator,

    #[token("(", priority = 6)]
    CommentStart,

    SuperDumbPlaceholder(&'hdr str),
}

#[derive(Clone, Debug, PartialEq)]
enum Stage {
    WantHost,
    SawHost,
    WantIdentifier,

    /// auth = ..
    WantAuthVersion,
    WantAuthEqual,
    WantAuthResult,
    GotAuthResult,

    /// spf = ...
    WantSpfVersion,
    WantSpfEqual,
    WantSpfResult,
    GotSpfResult,

    // dkim = ...
    WantDkimVersion,
    WantDkimEqual,
    WantDkimResult,
    GotDkimResult,

    // iprev = ...
    WantIpRevVersion,
    WantIpRevEqual,
    WantIpRevResult,
    GotIpRevResult,

    // ptype property values
    // waiting_on_propval must be Some(xProp)
    /*
    WantAuthPropEq,
    WantAUthPropVal,
    WantSpfPropEq,
    WantSpfPropVal,
    WantIpRevPropEq,
    WantIpRevPropVal,
    WantDkimPropEq,
    WantDkimPropVal,
    WantPolicyPropEq,
    WantPolicyPropVal,
     */
    // result = ".."
    WantReasonEqual,
    GotReason,
}

// State machine helpers
impl Stage {
    // Is the current token GotResult
    fn got_result(&self) -> bool {
        match self {
            Self::GotAuthResult
            | Self::GotSpfResult
            | Self::GotDkimResult
            | Self::GotIpRevResult => true,
            _ => false,
        }
    }
    // Is the current stage expecting resultset status
    fn is_cur_expect_resultset_want(&self) -> bool {
        match self {
            Self::WantAuthResult
            | Self::WantSpfResult
            | Self::WantDkimResult
            | Self::WantIpRevResult => true,
            _ => false,
        }
    }
    // Is the current stage expecting something after resulset
    fn is_cur_expect_resultset_got(&self) -> bool {
        match self {
            Self::GotAuthResult
            | Self::GotSpfResult
            | Self::GotDkimResult
            | Self::GotIpRevResult => true,
            _ => false,
        }
    }
    // Is the current stage expecting '=' equal for a result set
    fn is_cur_expect_resultset_equal(&self) -> bool {
        match self {
            Self::WantAuthEqual
            | Self::WantSpfEqual
            | Self::WantDkimEqual
            | Self::WantIpRevEqual => true,
            _ => false,
        }
    }
    // Reflect the relevant Result for given WantEqual
    fn equal_to_result(&mut self) -> bool {
        let new_stage = match self {
            Stage::WantAuthEqual => Stage::WantAuthResult,
            Stage::WantSpfEqual => Stage::WantSpfResult,
            Stage::WantDkimEqual => Stage::WantDkimResult,
            Stage::WantIpRevEqual => Stage::WantIpRevResult,
            _ => return false,
        };
        *self = new_stage;
        true
        //Some(new_stage)
    }
}

#[derive(Debug)]
enum ParseCurrentResultChoice<'hdr> {
    SmtpAuth(SmtpAuthResult<'hdr>),
    Spf(SpfResult<'hdr>),
    Dkim(DkimResult<'hdr>),
    IpRev(IpRevResult<'hdr>),
}

#[derive(Debug, Default)]
struct ParseCurrentResultCode<'hdr> {
    result: Option<ParseCurrentResultChoice<'hdr>>,
    //current_property: Option<PropTypeKey>,
    #[cfg(any(feature = "alloc", feature = "heapless"))]
    properties: Vec<PropType<'hdr>>,
    #[cfg(any(feature = "alloc", feature = "heapless"))]
    comments: Vec<&'hdr str>,
}

fn assign_result_code<'hdr>(
    token: AuthResultToken<'hdr>,
    stage: Stage,
    cur_res: &mut ParseCurrentResultCode<'hdr>,
) -> Result<Stage, ResultCodeError> {
    let mut new_res: ParseCurrentResultCode<'hdr> = ParseCurrentResultCode::default();
    match stage {
        Stage::WantAuthResult => {
            let result_code = SmtpAuthResultCode::try_from(token).map_err(|e| e)?;
            let mut smtp_auth_result = SmtpAuthResult::default();
            smtp_auth_result.code = result_code;
            new_res.result = Some(ParseCurrentResultChoice::SmtpAuth(smtp_auth_result));
            *cur_res = new_res;
            Ok(Stage::GotAuthResult)
        }
        Stage::WantSpfResult => {
            let result_code = SpfResultCode::try_from(token).map_err(|e| e)?;
            let mut spf_result = SpfResult::default();
            spf_result.code = result_code;
            new_res.result = Some(ParseCurrentResultChoice::Spf(spf_result));
            *cur_res = new_res;
            Ok(Stage::GotSpfResult)
        }
        Stage::WantDkimResult => {
            let result_code = DkimResultCode::try_from(token).map_err(|e| e)?;
            let mut dkim_result = DkimResult::default();
            dkim_result.code = result_code;
            new_res.result = Some(ParseCurrentResultChoice::Dkim(dkim_result));
            *cur_res = new_res;
            Ok(Stage::GotDkimResult)
        }
        Stage::WantIpRevResult => {
            let result_code = IpRevResultCode::try_from(token).map_err(|e| e)?;
            let mut iprev_result = IpRevResult::default();
            iprev_result.code = result_code;
            new_res.result = Some(ParseCurrentResultChoice::IpRev(iprev_result));
            *cur_res = new_res;
            Ok(Stage::GotIpRevResult)
        }
        // Policy ?
        Stage::GotDkimResult => match token {
            AuthResultToken::Policy => panic!("Bingo.."),
            _ => panic!("Nope. Token really was ... {:?}", token),
        },
        _ => Err(ResultCodeError::InvalidResultStage(stage.clone())),
    }
    //panic!("assign_result_code Token: {:?} - stage: {:?} - cur_res = {:?}", token, stage, cur_res);
}

impl<'hdr> TryFrom<&'hdr HeaderValue<'hdr>> for AuthenticationResults<'hdr> {
    type Error = ResultCodeError;

    fn try_from(hval: &'hdr HeaderValue<'hdr>) -> Result<Self, Self::Error> {
        let text = hval.as_text().unwrap();

        let mut host_lexer = HostVersionToken::lexer(&text);

        let host = match parse_host_version(&mut host_lexer) {
            Ok(host) => host,
            Err(e) => {
                return Err(e);
            }
        };

        let mut lexer: Lexer<'hdr, AuthResultToken<'hdr>> = host_lexer.morph();
        let mut res = Self::default();
        let mut stage = Stage::WantIdentifier;
        let mut cur_res = ParseCurrentResultCode::default();

        while let Some(token) = lexer.next() {
            match token {
                Ok(AuthResultToken::FieldSeparator) if stage.got_result() => {
                    stage = Stage::WantIdentifier;
                    panic!(
                                "OK TODO fieldSeparator Current_res at field sep = {:?} .. save it - span - {:?}, text - {:?}",
                                cur_res,
                                lexer.span(),
                                text
                            );
                    cur_res = ParseCurrentResultCode::default();
                }
                Ok(AuthResultToken::NoneNone) if stage == Stage::WantIdentifier => {
                    res.none_done = true;
                }
                Ok(AuthResultToken::Auth) if stage == Stage::WantIdentifier => {
                    stage = Stage::WantAuthEqual;
                }
                Ok(AuthResultToken::Spf) if stage == Stage::WantIdentifier => {
                    stage = Stage::WantSpfEqual;
                }
                Ok(AuthResultToken::Dkim) if stage == Stage::WantIdentifier => {
                    stage = Stage::WantDkimEqual;
                }
                Ok(AuthResultToken::IpRev) if stage == Stage::WantIdentifier => {
                    stage = Stage::WantIpRevEqual;
                }
                Ok(AuthResultToken::Equal) if stage.is_cur_expect_resultset_equal() => {
                    stage.equal_to_result();
                }
                Ok(AuthResultToken::Equal) if stage == Stage::WantReasonEqual => {
                    let mut reason_lexer: Lexer<'hdr, ReasonToken<'hdr>> = lexer.morph();
                    let reason_res = match parse_reason(&mut reason_lexer) {
                        Err(e) => return Err(e),
                        Ok(reason) => reason,
                    };
                    lexer = reason_lexer.morph();
                    stage = Stage::GotReason;
                }
                Ok(AuthResultToken::Reason) => {
                    stage = Stage::WantReasonEqual;
                }
                Ok(AuthResultToken::Policy) => {
                    let mut policy_lexer: Lexer<'hdr, PolicyToken<'hdr>> = lexer.morph();
                    let policy = match parse_policy(&mut policy_lexer) {
                        Ok(policy) => policy,
                        Err(e) => return Err(e),
                    };
                    lexer = policy_lexer.morph();
                }
                Ok(
                    AuthResultToken::Pass
                    | AuthResultToken::Fail
                    | AuthResultToken::TempError
                    | AuthResultToken::PermError
                    | AuthResultToken::NoneNone
                    | AuthResultToken::Neutral,
                ) if stage.is_cur_expect_resultset_want() => {
                    let new_stage = match assign_result_code(
                        token.expect("BUG: Matched err?!"),
                        stage.clone(),
                        &mut cur_res,
                    ) {
                        Err(e) => return Err(e),
                        Ok(new_stage) => new_stage,
                    };

                    let mut ptype_lexer = PtypeToken::lexer(lexer.remainder());

                    parse_ptype_properties(&mut ptype_lexer, &mut cur_res);

                    lexer.bump(ptype_lexer.span().end);
                }
                Ok(AuthResultToken::ForwardSlash) => {
                    let mut version_lexer = VersionToken::lexer(lexer.remainder());

                    /*
                    let new_stage = match stage {
                        Stage::WantAuthEqual => Stage::WantAuthResult,
                        Stage::WantSpfEqual => Stage::WantSpfResult,
                        Stage::WantDkimEqual => Stage::WantDkimResult,
                        Stage::WantIpRevEqual => Stage::WantIpRevResult,
                        _ => {
                            return Err(ResultCodeError::UnexpectedForwardSlash);
                        }
                    }; */

                    let version_res = match parse_version(&mut version_lexer) {
                        Ok(version) => version,
                        Err(e) => return Err(e),
                    };
                    //stage = new_stage;
                    lexer.bump(version_lexer.span().end);
                }
                Ok(AuthResultToken::CommentStart) => {
                    let mut comment_lexer: Lexer<'hdr, CommentToken<'hdr>> = lexer.morph();
                    match parse_comment(&mut comment_lexer) {
                        Ok(comment) => {}
                        Err(e) => return Err(e),
                    }
                    lexer = comment_lexer.morph();
                }
                Ok(_) => {
                    panic!(
                        "TODO stage({:?}) - Ok got Token {:?} span {:?} - source{:?}",
                        stage,
                        token,
                        lexer.span(),
                        lexer.source()
                    );
                }
                Err(_) => {
                    let cut_slice = &lexer.source()[lexer.span().start..];
                    let cut_span = &lexer.source()[lexer.span().start .. lexer.span().end];
                    panic!(
                        "Unrecognised at stage({:?}) span {:?} source {:?}\nClip/Span: {:?} - Clip/Remaining: {:?}",
                        stage,
                        lexer.span(),
                        lexer.source(),
                        cut_span,
                        cut_slice,
                    );
                }
            }
        }
        //panic!("res = {:?}", res);
        Ok(res)
    }
}
