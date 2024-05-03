use core::str::FromStr;
use logos::Logos;
//use strum_macros::{Display as StrumDisplay, EnumString};

#[cfg(feature = "mail_parse")]
use mail_parser::HeaderValue;

#[derive(Debug)]
pub enum ResultCodeError {
    Parse,
    InvalidDkimResult(String),
    InvalidSpfResult(String),
    InvalidIpRevResult(String),
}

/// DKIM Result Codes - s.2.7.1
//#[derive(Debug, EnumString, StrumDisplay)]
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
//#[derive(Debug, EnumString, StrumDisplay)]
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
//#[derive(Debug, EnumString, StrumDisplay)]
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

// TODO: Create separate tokenisers for hostname etc. w/o regexing MVP here.
#[derive(Debug, Logos)]
#[logos(skip r"[ \r\n]+")]
pub enum AuthResultToken<'hdr> {
    #[token("none")]
    NoneNone,

    // This also matches foo..bar - logos regex is limited - needs additional validation
    #[regex(r"([A-Za-z0-9][A-Za-z0-9\.\-]+)", |lex| lex.slice())]
    MaybeHostname(&'hdr str),

    // https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
    // logos does not support lookahead
    #[regex(r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)", |lex| lex.slice())]
    MaybeIPv4Addr(&'hdr str),

    // https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    // Too complex for logos regex, do separate validation
    #[regex(r"[A-F0-9]:[A-F0-9:]+", |lex| lex.slice())]
    MaybeIPv6Addr(&'hdr str),

    #[token("1")]
    VersionOne,

    #[token(";")]
    FieldSeparator,

    #[token("dkim")]
    Dkim,

    #[token("spf")]
    Spf,

    #[token("iprev")]
    IpRev,

    #[token("softfail")]
    SoftFail,

    #[token("fail")]
    Fail,

    #[token("neutral")]
    Neutral,

    #[token("pass")]
    Pass,

    #[token("temperror")]
    TempError,

    #[token("permerror")]
    PermError,

    #[token("policy")]
    Policy,

    #[token("=")]
    Equal,
    /* bah logos didn't do captures :)
    #[regex(r"dkim=(fail|neutral|none|pass|permerror|policy|temperror)", |lex| DkimResultCode::from_str(lex.slice()).unwrap_or_default())]
    DkimStatus(DkimResultCode),

    #[regex(r"spf=(none|pass|fail|softfail|policy|neutral|temperror|permerror)", |lex| SpfResultCode::from_str(lex.slice()).unwrap_or_default())]
    SpfStatus(SpfResultCode),

    #[regex(r"iprev=(pass|fail|temperror|permerror)", |lex| IpRevResultCode::from_str(lex.slice()).unwrap_or_default())]
    IpRevStatus(IpRevResultCode),
    */
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
    WantSpfEqual,
    WantSpfResult,
    GotSpfResult,
    WantDkimEqual,
    WantDkimResult,
    GotDkimResult,
    WantIpRevEqual,
    WantIpRevResult,
    GotIpRevResult,
}

impl<'hdr> From<&HeaderValue<'hdr>> for AuthenticationResults<'hdr> {
    fn from(hval: &HeaderValue<'hdr>) -> Self {
        let text = hval.as_text().unwrap();
        let mut lexer = AuthResultToken::lexer(&text);

        let mut res = Self::default();

        let mut stage = Stage::WantHost;

        let mut cur_spf = SpfResult::default();
        let mut cur_dkim = DkimResult::default();
        let mut cur_iprev = IpRevResult::default();

        while let Some(token) = lexer.next() {
            match token {
                Ok(AuthResultToken::MaybeHostname(ref host)) => {
                    if stage == Stage::WantHost {
                        res.host = Some(host);
                        stage = Stage::SawHost;
                    } else {
                        panic!("Invalid Hostname token at Stage {:?}", stage);
                    }
                }
                Ok(AuthResultToken::VersionOne) => {
                    // ..
                }
                Ok(AuthResultToken::FieldSeparator) => {
                    // ..
                    stage = Stage::WantIdentifier;
                }
                Ok(AuthResultToken::NoneNone) => {
                    if stage == Stage::WantIdentifier {
                        res.none_done = true;
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
                        Stage::WantSpfEqual => Stage::WantSpfResult,
                        Stage::WantDkimEqual => Stage::WantDkimEqual,
                        Stage::WantIpRevEqual => Stage::WantIpRevEqual,
                        _ => {
                            panic!("Invalid Equal token at Stage {:?}", stage);
                        }
                    };
                }
                // Result possible for all
                Ok(
                    AuthResultToken::Pass
                    | AuthResultToken::Fail
                    | AuthResultToken::TempError
                    | AuthResultToken::PermError,
                ) => {
                    let ok_token = token.expect("bug");
                    stage = match stage {
                        Stage::WantSpfResult => {
                            //let spf_res: Result<SpfResult<'hdr>, ResultCodeError> = token.expect("BUG").into();
                            let spf_res = SpfResultCode::try_from(ok_token);
                            match spf_res {
                                Ok(res) => {
                                    cur_spf = SpfResult::default();
                                    cur_spf.code = res;
                                }
                                Err(e) => panic!("Invalid SPF result"),
                            }
                            Stage::GotSpfResult
                        }
                        Stage::WantDkimResult => Stage::GotDkimResult,
                        Stage::WantIpRevResult => Stage::GotIpRevResult,
                        _ => {
                            panic!("Invalid Pass token at Stage {:?}", stage);
                        }
                    };
                }
                Ok(_) => {
                    panic!("Ok got Token {:?} on {:?}", token, text);
                }
                Err(_) => {
                    panic!("Unexpected token {:?} on {:?}", lexer.span(), text);
                }
            }
        }
        panic!("res = {:?}", res);
        res;
    }
}
