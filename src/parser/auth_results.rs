use logos::Logos;

/// DKIM Result Codes - s.2.7.1
#[derive(Debug)]
pub enum DkimResultCode {
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

/// SPF Result Codes - s.2.7.2
/// SPF defined in RFC 7208 s.2.6 - Results evaluation
#[derive(Debug)]
pub enum SpfResultCode {
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

/// IpRev Result Codes - s.2.7.3
#[derive(Debug)]
pub enum IpRevResultCode {
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

#[derive(Debug, Logos)]
#[logos(skip r"[ \r\n]+")]
enum AuthResultToken<'hdr> {
    #[regex(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$", |lex| lex.slice())]
    Hostname(&'hdr str),

    #[token(";")]
    FieldSeparator,

    #[token(r"^dkim=(fail|neutral|none|pass|permerror|policy|temperror)", |lex| lex.slice().parse::<DkimStatusCode>)]
    DkimStatus(DkimStatusCode),

    #[token(r"^spf=(none|pass|fail|softfail|policy|neutral|temperror|permerror)", |lex| lex.slice().parse::<SpfCode>)]
    SpfStatus(SpfStatusCode),

    #[token(r"^spf=(pass|fail|temperror|permerror)", |lex| lex.slice().parse::<ipRevCode>)]
    IpRevStatus(IpRevStatusCode),    
    
}
    
