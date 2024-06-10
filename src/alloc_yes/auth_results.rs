//! Allocating DkimResultsHandler, SpfResultsHandler, AuthResultsHandler, IpRevResultsHandler

use crate::auth::SmtpAuthResult;
use crate::dkim::DkimResult;
use crate::iprev::IpRevResult;
use crate::spf::SpfResult;

use crate::auth_results::*;

use crate::error::AuthResultsError;

/// Parsed Authentication-Results
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuthenticationResults<'hdr> {
    /// Relevant host to this record
    pub host: Option<HostVersion<'hdr>>,
    /// Parsed auth = .. records
    pub smtp_auth_result: Vec<SmtpAuthResult<'hdr>>,
    /// Parsed spf = .. records
    pub spf_result: Vec<SpfResult<'hdr>>,
    /// Parsed dkim = .. records
    pub dkim_result: Vec<DkimResult<'hdr>>,
    /// Parsed iprev = .. records
    pub iprev_result: Vec<IpRevResult<'hdr>>,
    /// Whether none was encountered denoting no result
    pub none_done: bool,
    /// Unparsed raw
    pub raw: Option<&'hdr str>,
    /// Parsing errors if any
    pub errors: Vec<AuthResultsError<'hdr>>,
}

/// Allocating type for parsed all Authentication-Results in email
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Default)]
pub struct MessageAuthStatus<'hdr> {
    /// Authentication-Results
    auth_results: Vec<AuthenticationResults<'hdr>>,
}

/// TODO: Fix errors
#[derive(Debug, PartialEq)]
pub enum MessageAuthStatusError {}

impl<'hdr> MessageAuthStatus<'hdr> {
    /// Parse all Authentication-Results into allocating Vec from external mail_parser::Message
    #[cfg(feature = "mail_parser")]
    pub fn from_mail_parser(
        msg: &'hdr mail_parser::Message<'hdr>,
    ) -> Result<Self, MessageAuthStatusError> {
        let mut new_self = Self {
            auth_results: vec![],
        };

        new_self.auth_results = msg
            .header_values("Authentication-Results")
            .map(|mh| mh.into())
            .collect();

        Ok(new_self)
    }
}

#[cfg(test)]
#[cfg(feature = "mail_parser")]
mod test {
    use super::*;
    use insta::assert_debug_snapshot;
    use rstest::rstest;
    use std::{fs::File, io::Read, path::PathBuf};

    fn load_test_data(file_location: &str) -> Vec<u8> {
        let mut file = File::open(file_location).unwrap();
        let mut data: Vec<u8> = vec![];
        file.read_to_end(&mut data).unwrap();
        data
    }

    #[rstest]
    fn from_mail_parser(#[files("test_data/*.eml")] file_path: PathBuf) {
        let new_snapshot_path = file_path.with_extension("snap");

        insta::with_settings!({snapshot_path => new_snapshot_path}, {
            insta::allow_duplicates! {
                let raw  = load_test_data(file_path.to_str().unwrap());
                let parser = mail_parser::MessageParser::default();
                let parsed_message = parser.parse(&raw).unwrap();
                let status = MessageAuthStatus::from_mail_parser(&parsed_message).unwrap();
                assert_debug_snapshot!(&status);
            }
        });
    }
}
