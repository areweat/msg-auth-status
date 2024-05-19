use core::str::FromStr;
use logos::{Lexer, Logos};
use strum_macros::{Display as StrumDisplay, EnumString};

use crate::dkim::*;

mod comment;
mod policy;
mod ptypes;
mod reason;
mod version;

use comment::{parse_comment, CommentToken};
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
    UnexpectedForwardSlash,
}

/// SMTP AUTH Result Codes - s.2.7.4
/// This SMTP Authentication (not DKIM)
//#[derive(Debug, Default, EnumString, StrumDisplay)]
//#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
#[derive(Debug, Default)]
pub enum SmtpAuthResultCode {
    #[default]
    Unknown,
    /// SMTP authentication was not attempted.
    NoneSmtp,
    /// The SMTP client authenticated to the server
    Pass,
    /// The SMTP client attempted to authenticate but was not successful
    Fail,
    /// The SMTP client attempted to authenticate but was not able to complete
    /// the attempt due to some error that is likely transient in nature
    TempError,
    /// The SMTP client attempted to authenticate but was not able to complete
    /// the attempt due to some error that is likely not transient in nature
    PermError,
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

use crate::dkim::*;
use crate::spf::*;

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

/// IpRev Result Codes - s.2.7.3
//#[derive(Debug, Default, EnumString, StrumDisplay)]
//#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
#[derive(Debug, Default)]
pub enum IpRevResultCode {
    #[default]
    Unknown,
    /// The DNS evaluation succeeded, i.e., the "reverse" and
    /// "forward" lookup results were returned and were in agreement.
    Pass,
    /// The DNS evaluation failed.  In particular, the "reverse" and
    /// "forward" lookups each produced results, but they were not in
    /// agreement, or the "forward" query completed but produced no
    /// result, e.g., a DNS RCODE of 3, commonly known as NXDOMAIN, or an
    /// RCODE of 0 (NOERROR) in a reply containing no answers, was
    /// returned.
    Fail,
    /// The DNS evaluation could not be completed due to some
    /// error that is likely transient in nature, such as a temporary DNS
    /// error, e.g., a DNS RCODE of 2, commonly known as SERVFAIL, or
    /// other error condition resulted.  A later attempt may produce a
    /// final result.
    TempError,
    /// The DNS evaluation could not be completed because no PTR
    /// data are published for the connecting IP address, e.g., a DNS
    /// RCODE of 3, commonly known as NXDOMAIN, or an RCODE of 0 (NOERROR)
    /// in a reply containing no answers, was returned.  This prevented
    /// completion of the evaluation.  A later attempt is unlikely to
    /// produce a final result.
    PermError,
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
pub enum HostnameFieldToken<'hdr> {
    #[token(";", priority = 1)]
    FieldSeparator,

    // https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
    // logos does not support lookahead
    #[regex(r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)", |lex| lex.slice(), priority = 1)]
    MaybeIPv4Addr(&'hdr str),

    // https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    // Too complex for logos regex, do separate validation
    #[regex(r"[A-F0-9]:[A-F0-9:]+", |lex| lex.slice(), priority = 2)]
    MaybeIPv6Addr(&'hdr str),

    // This also matches foo..bar - logos regex is limited - needs additional validation
    #[regex(r"([A-Za-z0-9][A-Za-z0-9\.\-]+)", |lex| lex.slice(), priority = 3)]
    MaybeHostname(&'hdr str),

    #[token("1", priority = 4)]
    VersionOne,

    #[token("(", priority = 5)]
    CommentStart,
}

#[derive(Debug)]
pub struct HostVer<'hdr> {
    host: &'hdr str,
    version: Option<u32>,
}

fn parse_host_ver<'hdr>(
    lexer: &mut Lexer<'hdr, HostnameFieldToken<'hdr>>,
) -> Result<HostVer<'hdr>, ResultCodeError> {
    let mut maybe_host: Option<&'hdr str> = None;
    let mut maybe_version: Option<u32> = None;

    let mut stage = Stage::WantHost;

    while let Some(token) = lexer.next() {
        match token {
            Ok(
                HostnameFieldToken::MaybeHostname(host)
                | HostnameFieldToken::MaybeIPv4Addr(host)
                | HostnameFieldToken::MaybeIPv6Addr(host),
            ) => {
                if stage == Stage::WantHost {
                    maybe_host = Some(host);
                    stage = Stage::SawHost;
                } else {
                    return Err(ResultCodeError::ParseHost(
                        "Hostname appearing twice?".to_string(),
                    ));
                }
            }
            Ok(HostnameFieldToken::VersionOne) => {
                maybe_version = Some(1);
            }
            Ok(HostnameFieldToken::FieldSeparator) => {
                break;
            }
            Ok(HostnameFieldToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(comment) => {}
                    Err(e) => return Err(e),
                }
                *lexer = HostnameFieldToken::lexer(comment_lexer.remainder());
            }
            _ => panic!(
                "parse_host_ver -- Invalid token {:?} - span = {:?} - source = {:?}",
                token,
                lexer.span(),
                lexer.source()
            ),
        }
    }

    match maybe_host {
        Some(host) => Ok(HostVer {
            host,
            version: maybe_version,
        }),
        None => Err(ResultCodeError::NoHostname),
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

    // TODO: separate below
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

    #[token("smtp.auth", priority = 2)]
    SmtpDotAuth,
    #[token("smtp.helo", priority = 2)]
    SmtpDotHelo,
    #[token("smtp.mailfrom", priority = 2)]
    SmtpDotMailFrom,
    #[token("header.a", priority = 2)]
    HeaderDotA,
    #[token("header.d", priority = 2)]
    HeaderDotD,
    #[token("header.i", priority = 2)]
    HeaderDotI,
    #[token("policy", priority = 3)]
    Policy,

    #[token("\\", priority = 3)]
    BackQuote,

    #[token("\"", priority = 3)]
    DoubleQuote,

    #[token(";", priority = 5)]
    FieldSeparator,

    #[token(".", priority = 5)]
    Dot,

    #[token("(", priority = 6)]
    CommentStart,

    SuperDumbPlaceholder(&'hdr str),
}

#[derive(Debug, Default)]
pub struct SmtpAuthResult<'hdr> {
    code: SmtpAuthResultCode,
    smtp_auth: Option<&'hdr str>,
    mail_from: Option<&'hdr str>,
}

/*
#[derive(Debug, Default)]
pub struct SpfResult<'hdr> {
    code: SpfResultCode,
    reason: Option<&'hdr str>,
    smtp_mailfrom: Option<&'hdr str>,
    smtp_helo: Option<&'hdr str>,
}
*/

/*
#[derive(Debug, Default)]
pub struct DkimResult<'hdr> {
    code: DkimResultCode,
    reason: Option<&'hdr str>,
    header_d: Option<&'hdr str>,
    header_i: Option<&'hdr str>,
    header_b: Option<&'hdr str>,
    header_a: Option<DkimAlgorithm<'hdr>>,
    header_s: Option<&'hdr str>,
} */

#[derive(Debug, Default)]
pub struct IpRevResult<'hdr> {
    code: IpRevResultCode,
    reason: Option<&'hdr str>,
    //    header_i: Option<&'hdr str>,
}

#[derive(Debug, Default)]
pub struct AuthenticationResults<'hdr> {
    a: Option<&'hdr str>,
    host: Option<&'hdr str>,
    smtp_auth_result: Vec<SmtpAuthResult<'hdr>>,
    spf_result: Vec<SpfResult<'hdr>>,
    dkim_result: Vec<DkimResult<'hdr>>,
    iprev_result: Vec<IpRevResult<'hdr>>,
    none_done: bool,
}

#[derive(Debug, PartialEq)]
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

impl Stage {
    fn got_result(&self) -> bool {
        match self {
            Self::GotAuthResult
            | Self::GotSpfResult
            | Self::GotDkimResult
            | Self::GotIpRevResult => true,
            _ => false,
        }
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
        _ => Err(ResultCodeError::InvalidResultStage(stage)),
    }
    //panic!("assign_result_code Token: {:?} - stage: {:?} - cur_res = {:?}", token, stage, cur_res);
}

impl<'hdr> TryFrom<&'hdr HeaderValue<'hdr>> for AuthenticationResults<'hdr> {
    type Error = ResultCodeError;

    fn try_from(hval: &'hdr HeaderValue<'hdr>) -> Result<Self, Self::Error> {
        let text = hval.as_text().unwrap();

        let mut host_lexer = HostnameFieldToken::lexer(&text);

        let host = match parse_host_ver(&mut host_lexer) {
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
                    //                    match stage {
                    //                        GotAuthResult | GotSpfResult | GotDkimResult | GotIpRevResult => {
                    // ..
                    stage = Stage::WantIdentifier;
                    panic!(
                                "OK TODO fieldSeparator Current_res at field sep = {:?} .. save it - span - {:?}, text - {:?}",
                                cur_res,
                                lexer.span(),
                                text
                            );
                    cur_res = ParseCurrentResultCode::default();
                    //                        }
                    //                        _ => {
                    //                            panic!("Invalid fieldSeparator after Stage {:?} - span: {:?} - text: {:?}", stage, lexer.span(), text);
                    //                        },
                }
                Ok(AuthResultToken::NoneNone) if stage == Stage::WantIdentifier => {
                    res.none_done = true;
                }
                Ok(AuthResultToken::Auth) => {
                    if stage == Stage::WantIdentifier {
                        stage = Stage::WantAuthEqual;
                    } else {
                        panic!("Invalid Auth token at Stage {:?}", stage);
                    }
                }
                Ok(AuthResultToken::Spf) => {
                    if stage == Stage::WantIdentifier {
                        stage = Stage::WantSpfEqual;
                    } else {
                        panic!("Invalid Spf token at Stage {:?}", stage);
                    }
                }
                Ok(AuthResultToken::Dkim) => {
                    if stage == Stage::WantIdentifier {
                        stage = Stage::WantDkimEqual;
                    } else {
                        panic!("Invalid Dkim token at Stage {:?}", stage);
                    }
                }
                Ok(AuthResultToken::IpRev) => {
                    if stage == Stage::WantIdentifier {
                        stage = Stage::WantIpRevEqual;
                    } else {
                        panic!("Invalid IpRev token at Stage {:?}", stage);
                    }
                }
                Ok(AuthResultToken::Equal) => {
                    stage = match stage {
                        Stage::WantAuthEqual => Stage::WantAuthResult,
                        Stage::WantSpfEqual => Stage::WantSpfResult,
                        Stage::WantDkimEqual => Stage::WantDkimResult,
                        Stage::WantIpRevEqual => Stage::WantIpRevResult,
                        Stage::WantReasonEqual => {
                            let mut reason_lexer: Lexer<'hdr, ReasonToken<'hdr>> = lexer.morph();
                            //let mut reason_lexer = ReasonToken::lexer(lexer.remainder());
                            let reason_res = match parse_reason(&mut reason_lexer) {
                                Err(e) => return Err(e),
                                Ok(reason) => reason,
                            };
                            lexer = reason_lexer.morph();
                            //lexer = AuthResultToken::lexer(reason_lexer.remainder());
                            Stage::GotReason
                        }
                        _ => {
                            panic!("Invalid Equal token at Stage {:?}", stage);
                        }
                    };
                }
                Ok(AuthResultToken::Reason) => {
                    stage = Stage::WantReasonEqual;
                }
                Ok(AuthResultToken::Policy) => {
                    //let mut policy_lexer = PolicyToken::lexer(lexer.remainder());
                    let mut policy_lexer: Lexer<'hdr, PolicyToken<'hdr>> = lexer.morph();
                    let policy = match parse_policy(&mut policy_lexer) {
                        Ok(policy) => policy,
                        Err(e) => return Err(e),
                    };
                    lexer = policy_lexer.morph();
                    //lexer = AuthResultToken::lexer(policy_lexer.remainder());
                }
                Ok(
                    AuthResultToken::Pass
                    | AuthResultToken::Fail
                    | AuthResultToken::TempError
                    | AuthResultToken::PermError
                    | AuthResultToken::NoneNone
                    | AuthResultToken::Neutral,
                ) => {
                    stage = match assign_result_code(
                        token.expect("BUG: Matched err?!"),
                        stage,
                        &mut cur_res,
                    ) {
                        Err(e) => return Err(e),
                        Ok(new_stage) => new_stage,
                    };
                }
                Ok(AuthResultToken::ForwardSlash) => {
                    let mut version_lexer = VersionToken::lexer(lexer.remainder());
                    //let mut version_lexer: Lexer<'hdr, VersionToken<'hdr>> = lexer.morph();

                    let new_stage = match stage {
                        Stage::WantAuthEqual => Stage::WantAuthResult,
                        Stage::WantSpfEqual => Stage::WantSpfResult,
                        Stage::WantDkimEqual => Stage::WantDkimResult,
                        Stage::WantIpRevEqual => Stage::WantIpRevResult,
                        _ => {
                            return Err(ResultCodeError::UnexpectedForwardSlash);
                        }
                    };

                    let version_res = match parse_version(&mut version_lexer) {
                        Ok(version) => version,
                        Err(e) => return Err(e),
                    };
                    stage = new_stage;
                    lexer.bump(version_lexer.span().end);
                }
                Ok(AuthResultToken::CommentStart) => {
                    //let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                    let mut comment_lexer: Lexer<'hdr, CommentToken<'hdr>> = lexer.morph();
                    match parse_comment(&mut comment_lexer) {
                        Ok(comment) => {}
                        Err(e) => return Err(e),
                    }
                    lexer = comment_lexer.morph();
                    //lexer = AuthResultToken::lexer(comment_lexer.remainder());
                }
                Ok(_) => {
                    panic!("Ok got Token {:?} on {:?}", token, text);
                }
                Err(_) => {
                    panic!(
                        "Unexpected token {:?} source {:?} on full {:?}",
                        lexer.span(),
                        lexer.source(),
                        text
                    );
                }
            }
        }
        //panic!("res = {:?}", res);
        Ok(res)
    }
}
