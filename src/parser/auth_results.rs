use core::str::FromStr;
use logos::{Lexer, Logos};
use strum_macros::{Display as StrumDisplay, EnumString};

mod policy;
mod reason;
use policy::{parse_policy, PolicyToken};
use reason::{parse_reason, ReasonToken};

#[cfg(feature = "mail_parse")]
use mail_parser::HeaderValue;

#[derive(Debug)]
pub enum ResultCodeError {
    Parse,
    ParseHost(String),
    InvalidDkimResult(String),
    InvalidSpfResult(String),
    InvalidIpRevResult(String),
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

/// DKIM Result Codes - s.2.7.1
//#[derive(Debug, Default, EnumString, StrumDisplay)]
//#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
#[derive(Debug, Default)]
pub enum DkimResultCode {
    #[default]
    Unknown,
    /// The message was not signed.
    NoneDkim,
    /// The message was signed, the signature or signatures were
    /// acceptable to the ADMD, and the signature(s) passed verification
    /// tests.
    Pass,
    /// The message was signed and the signature or signatures were
    /// acceptable to the ADMD, but they failed the verification test(s).
    Fail,
    /// The message was signed, but some aspect of the signature or
    /// signatures was not acceptable to the ADMD.
    Policy,
    /// The message was signed, but the signature or signatures
    /// contained syntax errors or were not otherwise able to be
    /// processed.  This result is also used for other failures not
    /// covered elsewhere in this list.
    Neutral,
    /// The message could not be verified due to some error that
    /// is likely transient in nature, such as a temporary inability to
    /// retrieve a public key.  A later attempt may produce a final
    /// result.
    TempError,
    /// The message could not be verified due to some error that
    /// is unrecoverable, such as a required header field being absent.  A
    /// later attempt is unlikely to produce a final result.
    PermError,
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

/// SPF Result Codes - s.2.7.2
/// SPF defined in RFC 7208 s.2.6 - Results evaluation
//#[derive(Debug, Default, EnumString, StrumDisplay)]
//#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
#[derive(Debug, Default)]
pub enum SpfResultCode {
    #[default]
    Unknown,
    /// Either (a) syntactically valid DNS domain name was extracted from the
    /// SMTP session that could be used as the one to be authorized, or (b) no
    /// SPF records were retrieved from the DNS.
    NoneSpf,
    /// An explicit statement that the client is authorized to inject mail with
    /// the given identity.
    Pass,
    /// An explicit statement that the client is not authorized to use the domain
    /// in the given identity.
    Fail,
    /// A weak statement by the publishing ADMD that the host is probably not
    /// authorized.  It has not published a stronger, more definitive policy that
    /// results in a "fail".
    SoftFail,
    /// RFC 8601 - Section 2.4
    /// Indication that some local policy mechanism was applied that augments or
    /// even replaces (i.e., overrides) the result returned by the authentication
    /// mechanism.  The property and value in this case identify the local policy
    /// that was applied and the result it returned.
    Policy,
    /// The ADMD has explicitly stated that it is not asserting whether the IP
    /// address is authorized.
    Neutral,
    /// The SPF verifier encountered a transient (generally DNS) error while
    /// performing the check.  A later retry may succeed without further DNS
    /// operator action.
    TempError,
    /// The domain's published records could not be correctly interpreted.
    /// This signals an error condition that definitely requires DNS operator
    /// intervention to be resolved.
    PermError,
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
#[logos(skip r"[ ]+")]
pub enum VersionToken<'hdr> {
    #[regex(r"[0-9]+", |lex| lex.slice(), priority = 1)]
    MaybeVersion(&'hdr str),

    #[token("(", priority = 2)]
    CommentStart,

    #[token("=", priority = 3)]
    Equal,
}

fn parse_version<'hdr>(
    lexer: &mut Lexer<'hdr, VersionToken<'hdr>>,
) -> Result<u32, ResultCodeError> {
    let mut res_version: Option<u32> = None;

    while let Some(token) = lexer.next() {
        match token {
            Ok(VersionToken::MaybeVersion(version_str)) => {
                let version_u32: u32 = version_str
                    .parse()
                    .map_err(|_| ResultCodeError::InvalidVersion)?;
                res_version = Some(version_u32);
            }
            Ok(VersionToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(comment) => {}
                    Err(e) => return Err(e),
                }
                *lexer = VersionToken::lexer(comment_lexer.remainder());
            }
            Ok(VersionToken::Equal) => {
                break;
            }
            _ => {
                panic!(
                    "parse_version -- Invalid token {:?} - span = {:?} - source = {:?}",
                    token,
                    lexer.span(),
                    lexer.source()
                );
            }
        }
    }

    match res_version {
        Some(v) => Ok(v),
        None => Err(ResultCodeError::NoAssociatedVersion),
    }
}

#[derive(Debug, Logos)]
pub enum CommentToken<'hdr> {
    #[token(")", priority = 1)]
    CommentEnd,

    #[regex("[^)]+", |lex| lex.slice(), priority = 2)]
    Comment(&'hdr str),
}

fn parse_comment<'hdr>(lexer: &mut Lexer<'hdr, CommentToken<'hdr>>) -> Result<(), ResultCodeError> {
    while let Some(token) = lexer.next() {
        match token {
            Ok(CommentToken::Comment(comment)) => {
                // ignore
            }
            Ok(CommentToken::CommentEnd) => {
                return Ok(());
            }
            _ => {
                panic!(
                    "parse_comment -- Invalid token {:?} - span = {:?} - source = {:?}",
                    token,
                    lexer.span(),
                    lexer.source()
                );
            }
        }
    }
    Err(ResultCodeError::RunAwayComment)
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

    //#[regex(r#""([^"\\]|\\t|\\u|\\n|\\")*""#)]
    //StringLiteral(&'hdr str),

    // Property types are defined in RFC 7410
    // And RFC 8601 s. 2.3 based on RFC 7001
    #[token("smtp.auth", priority = 2)]
    SmtpDotAuth,
    #[token("smtp.mailfrom", priority = 2)]
    SmtpDotMailFrom,
    #[token("header.a", priority = 2)]
    HeaderDotA,
    #[token("header.d", priority = 2)]
    HeaderDotD,
    #[token("header.i", priority = 1)]
    HeaderDotI,
    #[token("policy", priority = 1)]
    Policy,

    #[token("\\", priority = 3)]
    BackQuote,

    #[token("\"", priority = 3)]
    DoubleQuote,

    #[token(";", priority = 5)]
    FieldSeparator,

    #[token("(", priority = 6)]
    CommentStart,

    SuperDumbPlaceholder(&'hdr str),
}

#[derive(Debug, Default)]
pub struct SmtpAuthResult<'hdr> {
    code: SmtpAuthResultCode,
    smtp_auth: Option<&'hdr str>,
}

#[derive(Debug, Default)]
pub struct SpfResult<'hdr> {
    code: SpfResultCode,
    reason: Option<&'hdr str>,
    header_i: Option<&'hdr str>,
}

#[derive(Debug, Default)]
pub struct DkimResult<'hdr> {
    code: DkimResultCode,
    reason: Option<&'hdr str>,
    //    header_i: Option<&'hdr str>,
}

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

    // result = ".."
    WantReasonEqual,
    GotReason,
}

#[derive(Debug)]
pub enum ParseCurrentResultChoice<'hdr> {
    SmtpAuth(SmtpAuthResult<'hdr>),
    Spf(SpfResult<'hdr>),
    Dkim(DkimResult<'hdr>),
    IpRev(IpRevResult<'hdr>),
}

#[derive(Debug, Default)]
pub struct ParseCurrentResultCode<'hdr> {
    result: Option<ParseCurrentResultChoice<'hdr>>,
}

fn assign_result_code<'hdr>(
    token: AuthResultToken<'hdr>,
    stage: Stage,
    cur_res: &mut ParseCurrentResultCode<'hdr>,
) -> Result<Stage, ResultCodeError> {
    match stage {
        Stage::WantAuthResult => {
            let result_code = SmtpAuthResultCode::try_from(token).map_err(|e| e)?;
            let mut smtp_auth_result = SmtpAuthResult::default();
            smtp_auth_result.code = result_code;
            *cur_res = ParseCurrentResultCode {
                result: Some(ParseCurrentResultChoice::SmtpAuth(smtp_auth_result)),
            };
            Ok(Stage::GotAuthResult)
        }
        Stage::WantSpfResult => {
            let result_code = SpfResultCode::try_from(token).map_err(|e| e)?;
            let mut spf_result = SpfResult::default();
            spf_result.code = result_code;
            *cur_res = ParseCurrentResultCode {
                result: Some(ParseCurrentResultChoice::Spf(spf_result)),
            };
            Ok(Stage::GotSpfResult)
        }
        Stage::WantDkimResult => {
            let result_code = DkimResultCode::try_from(token).map_err(|e| e)?;
            let mut dkim_result = DkimResult::default();
            dkim_result.code = result_code;
            *cur_res = ParseCurrentResultCode {
                result: Some(ParseCurrentResultChoice::Dkim(dkim_result)),
            };
            Ok(Stage::GotDkimResult)
        }
        Stage::WantIpRevResult => {
            let result_code = IpRevResultCode::try_from(token).map_err(|e| e)?;
            let mut iprev_result = IpRevResult::default();
            iprev_result.code = result_code;
            *cur_res = ParseCurrentResultCode {
                result: Some(ParseCurrentResultChoice::IpRev(iprev_result)),
            };
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

impl<'hdr> TryFrom<&HeaderValue<'hdr>> for AuthenticationResults<'hdr> {
    type Error = ResultCodeError;

    fn try_from(hval: &HeaderValue<'hdr>) -> Result<Self, Self::Error> {
        let text = hval.as_text().unwrap();

        let mut host_lexer = HostnameFieldToken::lexer(&text);

        let host = match parse_host_ver(&mut host_lexer) {
            Ok(host) => host,
            Err(e) => {
                return Err(e);
            }
        };

        let remainder = host_lexer.remainder();

        let mut lexer = AuthResultToken::lexer(remainder);

        let mut res = Self::default();

        let mut stage = Stage::WantIdentifier;

        let mut cur_res = ParseCurrentResultCode::default();

        //let mut cur_spf = SpfResult::default();
        //let mut cur_dkim = DkimResult::default();
        //let mut cur_iprev = IpRevResult::default();

        while let Some(token) = lexer.next() {
            match token {
                Ok(AuthResultToken::FieldSeparator) => {
                    // ..
                    stage = Stage::WantIdentifier;
                    panic!(
                        "Current_res at field sep = {:?} .. save it - span - {:?}, text - {:?}",
                        cur_res,
                        lexer.span(),
                        text
                    );
                    cur_res = ParseCurrentResultCode::default();
                }
                Ok(AuthResultToken::NoneNone) if stage == Stage::WantIdentifier => {
                    //                    if stage == Stage::WantIdentifier {
                    res.none_done = true;
                    //                    }
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
                            let mut reason_lexer = ReasonToken::lexer(lexer.remainder());
                            let reason_res = match parse_reason(&mut reason_lexer) {
                                Err(e) => return Err(e),
                                Ok(reason) => reason,
                            };
                            lexer = AuthResultToken::lexer(reason_lexer.remainder());
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
                    let mut policy_lexer = PolicyToken::lexer(lexer.remainder());
                    let policy = match parse_policy(&mut policy_lexer) {
                        Ok(policy) => policy,
                        Err(e) => return Err(e),
                    };
                    lexer = AuthResultToken::lexer(policy_lexer.remainder());
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
                    lexer = AuthResultToken::lexer(version_lexer.remainder());
                }
                Ok(AuthResultToken::CommentStart) => {
                    let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                    match parse_comment(&mut comment_lexer) {
                        Ok(comment) => {}
                        Err(e) => return Err(e),
                    }
                    lexer = AuthResultToken::lexer(comment_lexer.remainder());
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
