//! Property types

mod auth;
mod dkim;
mod dmarc;
mod iprev;
//mod policy;
mod spf;

pub use auth::{AuthProperty, AuthPtype};
pub use dkim::{DkimProperty, DkimPtype};
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

    #[regex(r"\s+", |lex| lex.slice(), priority = 5)]
    WhiteSpaces(&'hdr str),
}

#[derive(Debug)]
enum PtypeStage {
    WantPtype,
    GotPtype,
    WantDot,
    WantPropertyKey,
    GotPropertyKey,
    WantEq,
    GotEq,
    WantPropertyVal,
    GotPropertyVal,
}

pub fn parse_ptype_properties<'hdr>(
    lexer: &mut Lexer<'hdr, PtypeToken<'hdr>>,
    cur_res: &mut ParseCurrentResultCode<'hdr>,
) -> Result<u32, ResultCodeError> {
    let mut properties_count = 0;
    let mut stage = PtypeStage::WantPtype;

    while let Some(token) = lexer.next() {
        match token {
            //Ok(PtypeSmtp ZZZ
            Ok(PtypeToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(comment) => {}
                    Err(e) => return Err(e),
                }
                *lexer = PtypeToken::lexer(comment_lexer.remainder());
            }
            Ok(PtypeToken::FieldSep) => {
                break;
            }
            Ok(PtypeToken::Equal) => {}
            _ => {
                panic!(
                    "parse_ptypes_properties -- Invalid token {:?} - span = {:?} - source = {:?}",
                    token,
                    lexer.span(),
                    lexer.source()
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
