//! Parsing for Auth Results using Logos

use logos::{Lexer, Logos};

use crate::auth::{SmtpAuthResult, SmtpAuthResultCode};
use crate::dkim::{DkimResult, DkimResultCode};
use crate::error::AuthResultsError;
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

#[cfg(feature = "mail_parser")]
use mail_parser::HeaderValue;

impl TryFrom<AuthResultToken<'_>> for SmtpAuthResultCode {
    type Error = AuthResultsError;

    fn try_from(token: AuthResultToken<'_>) -> Result<Self, Self::Error> {
        let res = match token {
            AuthResultToken::NoneNone => Self::NoneSmtp,
            AuthResultToken::Pass => Self::Pass,
            AuthResultToken::Fail => Self::Fail,
            AuthResultToken::TempError => Self::TempError,
            AuthResultToken::PermError => Self::PermError,
            _ => return Err(AuthResultsError::InvalidSmtpAuthResult("".to_string())),
        };
        Ok(res)
    }
}

impl TryFrom<AuthResultToken<'_>> for DkimResultCode {
    type Error = AuthResultsError;

    fn try_from(token: AuthResultToken<'_>) -> Result<Self, Self::Error> {
        let res = match token {
            AuthResultToken::NoneNone => Self::NoneDkim,
            AuthResultToken::Pass => Self::Pass,
            AuthResultToken::Fail => Self::Fail,
            AuthResultToken::Policy => Self::Policy,
            AuthResultToken::Neutral => Self::Neutral,
            AuthResultToken::TempError => Self::TempError,
            AuthResultToken::PermError => Self::PermError,
            _ => return Err(AuthResultsError::InvalidDkimResult("".to_string())),
        };
        Ok(res)
    }
}

impl TryFrom<AuthResultToken<'_>> for SpfResultCode {
    type Error = AuthResultsError;

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
            _ => return Err(AuthResultsError::InvalidSpfResult("".to_string())),
        };
        Ok(res)
    }
}

impl TryFrom<AuthResultToken<'_>> for IpRevResultCode {
    type Error = AuthResultsError;

    fn try_from(token: AuthResultToken<'_>) -> Result<Self, Self::Error> {
        let res = match token {
            AuthResultToken::Pass => Self::Pass,
            AuthResultToken::Fail => Self::Fail,
            AuthResultToken::TempError => Self::TempError,
            AuthResultToken::PermError => Self::PermError,
            _ => return Err(AuthResultsError::InvalidIpRevResult("".to_string())),
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
    WantAuthEqual,
    WantAuthResult,

    /// spf = ...
    WantSpfEqual,
    WantSpfResult,

    // dkim = ...
    WantDkimEqual,
    WantDkimResult,

    // iprev = ...
    WantIpRevEqual,
    WantIpRevResult,
}

// State machine helpers
impl Stage {
    // Is the current stage expecting resultset status
    fn is_cur_expect_resultset_want(&self) -> bool {
        matches!(
            self,
            Self::WantAuthResult
                | Self::WantSpfResult
                | Self::WantDkimResult
                | Self::WantIpRevResult
        )
    }
    // Is the current stage expecting '=' equal for a result set
    fn is_cur_expect_resultset_equal(&self) -> bool {
        matches!(
            self,
            Self::WantAuthEqual | Self::WantSpfEqual | Self::WantDkimEqual | Self::WantIpRevEqual
        )
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
    }
}

#[derive(Clone, Debug)]
enum ParseCurrentResultChoice<'hdr> {
    SmtpAuth(SmtpAuthResult<'hdr>),
    Spf(SpfResult<'hdr>),
    Dkim(DkimResult<'hdr>),
    IpRev(IpRevResult<'hdr>),
}

impl<'hdr> ParseCurrentResultChoice<'hdr> {
    fn set_reason(&mut self, reason: &'hdr str) {
        if let ParseCurrentResultChoice::Dkim(ref mut dkim_res) = self {
            dkim_res.reason = Some(reason);
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ParseCurrentResultCode<'hdr> {
    result: Option<ParseCurrentResultChoice<'hdr>>,
}

fn assign_result_code<'hdr>(
    token: AuthResultToken<'hdr>,
    stage: Stage,
    cur_res: &mut ParseCurrentResultCode<'hdr>,
) -> Result<(), AuthResultsError> {
    let mut new_res: ParseCurrentResultCode<'hdr> = ParseCurrentResultCode::default();

    match stage {
        Stage::WantAuthResult => {
            let code = SmtpAuthResultCode::try_from(token)?;
            let smtp_auth_result = SmtpAuthResult {
                code,
                ..Default::default()
            };
            new_res.result = Some(ParseCurrentResultChoice::SmtpAuth(smtp_auth_result));
            *cur_res = new_res;
            Ok(())
        }
        Stage::WantSpfResult => {
            let code = SpfResultCode::try_from(token)?;
            let spf_result = SpfResult {
                code,
                ..Default::default()
            };
            new_res.result = Some(ParseCurrentResultChoice::Spf(spf_result));
            *cur_res = new_res;
            Ok(())
        }
        Stage::WantDkimResult => {
            let code = DkimResultCode::try_from(token)?;
            let dkim_result = DkimResult {
                code,
                ..Default::default()
            };
            new_res.result = Some(ParseCurrentResultChoice::Dkim(dkim_result));
            *cur_res = new_res;
            Ok(())
        }
        Stage::WantIpRevResult => {
            let code = IpRevResultCode::try_from(token)?;
            let iprev_result = IpRevResult {
                code,
                ..Default::default()
            };
            new_res.result = Some(ParseCurrentResultChoice::IpRev(iprev_result));
            *cur_res = new_res;
            Ok(())
        }
        _ => Err(AuthResultsError::InvalidResultStage),
    }
}

impl<'hdr> From<&'hdr HeaderValue<'hdr>> for AuthenticationResults<'hdr> {
    fn from(hval: &'hdr HeaderValue<'hdr>) -> Self {
        let mut res = Self {
            raw: hval.as_text(),
            ..Default::default()
        };

        let text = match hval.as_text() {
            None => {
                res.error = Some(AuthResultsError::NoHeader);
                return res;
            }
            Some(text) => text,
        };

        let mut host_lexer = HostVersionToken::lexer(text);

        let host = match parse_host_version(&mut host_lexer) {
            Ok(host) => host,
            Err(e) => {
                res.error = Some(e);
                return res;
            }
        };

        let mut lexer: Lexer<'hdr, AuthResultToken<'hdr>> = host_lexer.morph();
        res.host = Some(host);

        let mut stage = Stage::WantIdentifier;
        let mut cur_res = ParseCurrentResultCode::default();

        let mut raw_part_start = 0;

        while let Some(token) = lexer.next() {
            match token {
                Ok(AuthResultToken::NoneNone) if stage == Stage::WantIdentifier => {
                    res.none_done = true;
                }
                Ok(AuthResultToken::Auth) if stage == Stage::WantIdentifier => {
                    stage = Stage::WantAuthEqual;
                    raw_part_start = lexer.span().start;
                }
                Ok(AuthResultToken::Spf) if stage == Stage::WantIdentifier => {
                    stage = Stage::WantSpfEqual;
                    raw_part_start = lexer.span().start;
                }
                Ok(AuthResultToken::Dkim) if stage == Stage::WantIdentifier => {
                    stage = Stage::WantDkimEqual;
                    raw_part_start = lexer.span().start;
                }
                Ok(AuthResultToken::IpRev) if stage == Stage::WantIdentifier => {
                    stage = Stage::WantIpRevEqual;
                    raw_part_start = lexer.span().start;
                }
                Ok(AuthResultToken::Equal) if stage.is_cur_expect_resultset_equal() => {
                    stage.equal_to_result();
                }
                // TODO: This is not handled atm - it's cursed.
                Ok(AuthResultToken::Policy) => {
                    let mut policy_lexer: Lexer<'hdr, PolicyToken<'hdr>> = lexer.morph();
                    let _policy = match parse_policy(&mut policy_lexer) {
                        Ok(policy) => policy,
                        Err(e) => {
                            res.error = Some(e);
                            break;
                        }
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
                    if let Err(e) = assign_result_code(
                        token.expect("BUG: Matched err?!"),
                        stage.clone(),
                        &mut cur_res,
                    ) {
                        res.error = Some(e);
                        break;
                    }

                    let lexer_end = lexer.span().end;
                    let mut ptype_lexer = PtypeToken::lexer(lexer.remainder());

                    let raw_part_end =
                        match parse_ptype_properties(&mut ptype_lexer, &mut cur_res.result) {
                            Err(e) => {
                                res.error = Some(e);
                                break;
                            }
                            Ok(raw_part_end) => raw_part_end,
                        };

                    lexer.bump(ptype_lexer.span().end);

                    stage = Stage::WantIdentifier;
                    match cur_res.result {
                        Some(ParseCurrentResultChoice::Dkim(mut dkim_res)) => {
                            dkim_res.raw =
                                Some(&lexer.source()[raw_part_start..lexer_end + raw_part_end]);
                            res.dkim_result.push(dkim_res)
                        }
                        Some(ParseCurrentResultChoice::IpRev(mut iprev_res)) => {
                            iprev_res.raw =
                                Some(&lexer.source()[raw_part_start..lexer_end + raw_part_end]);
                            res.iprev_result.push(iprev_res)
                        }
                        Some(ParseCurrentResultChoice::Spf(mut spf_res)) => {
                            spf_res.raw =
                                Some(&lexer.source()[raw_part_start..lexer_end + raw_part_end]);
                            res.spf_result.push(spf_res)
                        }
                        Some(ParseCurrentResultChoice::SmtpAuth(mut auth_res)) => {
                            auth_res.raw =
                                Some(&lexer.source()[raw_part_start..lexer_end + raw_part_end]);
                            res.smtp_auth_result.push(auth_res)
                        }
                        _ => {
                            res.error = Some(AuthResultsError::ParseCurrentPushNotImplemented);
                            break;
                        }
                    }
                    cur_res = ParseCurrentResultCode::default();
                }
                Ok(AuthResultToken::ForwardSlash) => {
                    let mut version_lexer = VersionToken::lexer(lexer.remainder());

                    // TODO: Care about version ?
                    let _version_res = match parse_version(&mut version_lexer) {
                        Ok(version) => version,
                        Err(e) => {
                            res.error = Some(e);
                            break;
                        }
                    };
                    lexer.bump(version_lexer.span().end);
                }
                Ok(AuthResultToken::CommentStart) => {
                    let mut comment_lexer: Lexer<'hdr, CommentToken<'hdr>> = lexer.morph();
                    match parse_comment(&mut comment_lexer) {
                        Ok(_comment) => {} // TODO: keep comments?
                        Err(e) => {
                            res.error = Some(e);
                            break;
                        }
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
                    let cut_span = &lexer.source()[lexer.span().start..lexer.span().end];
                    panic!(
                        "Unrecognised at stage({:?}) span {:?} source {:?}\nClip/Span: {:?} - Clip/Remaining: {:?}\n Case: {:?}",
                        stage,
                        lexer.span(),
                        lexer.source(),
                        cut_span,
                        cut_slice,
                        text,
                    );
                }
            }
        }
        res
    }
}
