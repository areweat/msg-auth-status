//! Supplementary Verifier API
//!
//! This is a best effort implementation for now and may not work in all scenarios.

#[cfg(any(feature = "alloc", feature = "std"))]
use crate::alloc_yes::MessageAuthStatus;

use crate::addr::AddrSpec;
use crate::dkim::DkimResultCode;

use crate::parser::addr_spec::{parse_addr_spec, AddrSpecToken};

use crate::error::ReturnPathVerifierError;

use logos::Logos;

/// Verify that the `Return-Path` is authenticated
#[derive(Debug)]
pub struct ReturnPathVerifier<'hdr> {
    auth_status: &'hdr MessageAuthStatus<'hdr>,
    return_path: AddrSpec<'hdr>,
}

// Validate that Return-Path exists exactly only once and return it
#[cfg(feature = "mail_parser")]
fn exact_once_return_path<'hdr>(
    msg: &'hdr mail_parser::Message<'hdr>,
) -> Result<AddrSpec<'hdr>, ReturnPathVerifierError<'hdr>> {
    let mut items = msg.header_values("Return-Path");

    let candidate = if let Some(item) = items.next() {
        match item.as_text() {
            Some(text) => text,
            None => return Err(ReturnPathVerifierError::NoHeader),
        }
    } else {
        return Err(ReturnPathVerifierError::NoHeader);
    };

    if items.next().is_some() {
        return Err(ReturnPathVerifierError::MultipleNotAllowed);
    }

    let mut lex = AddrSpecToken::lexer(candidate);
    let parsed_return_path = match parse_addr_spec(&mut lex, true) {
        Ok(parsed) => parsed,
        Err(e) => return Err(ReturnPathVerifierError::InvalidHeader(e)),
    };

    Ok(parsed_return_path)
}

/// Return-Path verifier Status
#[derive(Debug, PartialEq)]
pub enum ReturnPathVerifierStatus {
    /// No DKIM results seen related to Return-path and header.d Authentication DKIM Result code
    Nothing,
    /// Seen at least one "Pass" DKIM Result code in Authentication-Results relevant to Return-Path
    Pass,
    /// Seen no "Pass" DKIM Result code in Authentication-Results relevant to Return-Path
    Fail,
}

// Check one AuthenticationResult header's DKIM Resutls against Domain
// Since hosts may have spotty algorithm support - at least one DKIM pass is required for header.d
fn check_dkim_res<'hdr>(
    res: &'hdr crate::alloc_yes::AuthenticationResults<'hdr>,
    domain: &'hdr str,
) -> ReturnPathVerifierStatus {
    let mut ret = ReturnPathVerifierStatus::Nothing;
    let dkim_res_iter = res.dkim_result.iter();
    for dkim_res in dkim_res_iter {
        if let Some(header_d) = dkim_res.header_d {
            if header_d == domain {
                let new_ret = match dkim_res.code {
                    DkimResultCode::Pass => return ReturnPathVerifierStatus::Pass,
                    DkimResultCode::Fail => Some(ReturnPathVerifierStatus::Fail),
                    DkimResultCode::TempError => Some(ReturnPathVerifierStatus::Fail),
                    DkimResultCode::PermError => Some(ReturnPathVerifierStatus::Fail),
                    DkimResultCode::Neutral => None,
                    DkimResultCode::NoneDkim => None,
                    DkimResultCode::Unknown => None,
                    DkimResultCode::Policy => None,
                };
                // One pass is enough for given header.d == domain
                if let Some(new_ret) = new_ret {
                    ret = new_ret;
                }
            }
        }
    }
    ret
}

impl<'hdr> ReturnPathVerifier<'hdr> {
    /// Construct Verifier from alloc_yes AuthenticationResults and mail_parser Headers containing Return-Path
    #[cfg(all(any(feature = "alloc", feature = "std"), feature = "mail_parser"))]
    pub fn from_alloc_yes(
        auth_status: &'hdr MessageAuthStatus<'hdr>,
        msg: &'hdr mail_parser::Message<'hdr>,
    ) -> Result<Self, ReturnPathVerifierError<'hdr>> {
        let return_path = exact_once_return_path(msg)?;
        Ok(Self {
            auth_status,
            return_path,
        })
    }
    /// Verify that Auth-Results contain at least one pass for DKIM header.d relevant to Return-Path header
    pub fn verify(&self) -> Result<ReturnPathVerifierStatus, ReturnPathVerifierError<'hdr>> {
        let mut dkim_pass_selector = false;
        let res_iter = self.auth_status.auth_results.iter();

        for res in res_iter {
            // Host may have multiple signature methods - one of many must pass
            match check_dkim_res(res, self.return_path.domain) {
                ReturnPathVerifierStatus::Fail => {}
                ReturnPathVerifierStatus::Pass => {
                    dkim_pass_selector = true;
                    break;
                }
                ReturnPathVerifierStatus::Nothing => {}
            }
        }

        match dkim_pass_selector {
            true => Ok(ReturnPathVerifierStatus::Pass),
            false => Ok(ReturnPathVerifierStatus::Fail),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "mail_parser")]
mod test {
    use super::*;
    use rstest::rstest;
    use std::{fs::File, io::Read, path::PathBuf};

    use crate::alloc_yes::MessageAuthStatus;

    fn load_test_data(file_location: &PathBuf) -> Vec<u8> {
        let mut file = File::open(file_location).unwrap();
        let mut data: Vec<u8> = vec![];
        file.read_to_end(&mut data).unwrap();
        data
    }

    #[rstest]
    #[case("to_in_protonmail.eml", Ok(ReturnPathVerifierStatus::Pass))]
    #[case("to_in_fastmail.eml", Ok(ReturnPathVerifierStatus::Pass))]
    #[case("to_in_areweat.eml", Ok(ReturnPathVerifierStatus::Pass))]
    #[case("fail_to_in_areweat.eml", Ok(ReturnPathVerifierStatus::Fail))]
    fn from_mail_parser(
        #[case] file: &'static str,
        #[case] expected: Result<ReturnPathVerifierStatus, ReturnPathVerifierError<'static>>,
    ) {
        let path = PathBuf::from("test_data");
        let full_path = path.join(file);
        let raw = load_test_data(&full_path);
        let parser = mail_parser::MessageParser::default();
        let parsed_message = parser.parse(&raw).unwrap();
        let status = MessageAuthStatus::from_mail_parser(&parsed_message).unwrap();
        let verifier = ReturnPathVerifier::from_alloc_yes(&status, &parsed_message).unwrap();

        assert_eq!(verifier.verify(), expected);
    }
}
