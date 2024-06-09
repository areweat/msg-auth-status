//! Hostname / IP Address parsing

use super::Stage;
use super::{parse_comment, CommentToken};

use crate::auth_results::HostVersion;
use crate::error::AuthResultsError;

use logos::{Lexer, Logos};

#[derive(Debug, Logos)]
#[logos(skip r"[ \r\n]+")]
pub enum HostVersionToken<'hdr> {
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

pub fn parse_host_version<'hdr>(
    lexer: &mut Lexer<'hdr, HostVersionToken<'hdr>>,
) -> Result<HostVersion<'hdr>, AuthResultsError> {
    let mut maybe_host: Option<&'hdr str> = None;
    let mut maybe_version: Option<u32> = None;

    let mut stage = Stage::WantHost;

    while let Some(token) = lexer.next() {
        match token {
            Ok(
                HostVersionToken::MaybeHostname(host)
                | HostVersionToken::MaybeIPv4Addr(host)
                | HostVersionToken::MaybeIPv6Addr(host),
            ) => {
                if stage == Stage::WantHost {
                    maybe_host = Some(host);
                    stage = Stage::SawHost;
                } else {
                    return Err(AuthResultsError::ParseHost(
                        "Hostname appearing twice?".to_string(),
                    ));
                }
            }
            Ok(HostVersionToken::VersionOne) => {
                maybe_version = Some(1);
            }
            Ok(HostVersionToken::FieldSeparator) => {
                break;
            }
            Ok(HostVersionToken::CommentStart) => {
                let mut comment_lexer = CommentToken::lexer(lexer.remainder());
                match parse_comment(&mut comment_lexer) {
                    Ok(_comment) => {}
                    Err(e) => return Err(e),
                }
                *lexer = HostVersionToken::lexer(comment_lexer.remainder());
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
        Some(host) => Ok(HostVersion {
            host,
            version: maybe_version,
        }),
        None => Err(AuthResultsError::NoHostname),
    }
}
