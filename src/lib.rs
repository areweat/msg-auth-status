#![warn(
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![doc = include_str!("../README.md")]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

//--------------------------------------------------------
// All public types
//--------------------------------------------------------

mod types;
pub use types::*;

pub mod auth;
pub mod dkim;
pub mod iprev;
pub mod spf;

use dkim::DkimSignature;

//--------------------------------------------------------
// Parsing implementations with type conversions
//--------------------------------------------------------

mod parser;

//--------------------------------------------------------
// Public API non-type based
//--------------------------------------------------------

#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Default)]
pub struct MessageAuthStatus<'hdr> {
    auth_results: Vec<AuthenticationResults<'hdr>>,
}

#[derive(Debug, PartialEq)]
pub enum MessageAuthStatusError {}

impl<'hdr> MessageAuthStatus<'hdr> {
    /// Parse all Authentication-Results into allocating Vec from external mail_parser::Message
    #[cfg(feature = "mail_parser")]
    pub fn alloc_from_mail_parser(
        msg: &'hdr mail_parser::Message<'hdr>,
    ) -> Result<Self, MessageAuthStatusError> {
        let mut new_self = Self {
            auth_results: vec![],
        };

        new_self.auth_results = msg
            .header_values("Authentication-Results")
            .into_iter()
            .map(|mh| mh.try_into().unwrap())
            .collect();

        Ok(new_self)
    }
}

#[derive(Debug, PartialEq)]
pub enum DkimSignaturesError {}

#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Default)]
pub struct DkimSignatures<'hdr> {
    dkim_signatures: Vec<DkimSignature<'hdr>>,
}

impl<'hdr> DkimSignatures<'hdr> {
    /// Parse all DKIM Signatures into allocating Vec from mail_parser::Message
    #[cfg(feature = "mail_parser")]
    pub fn alloc_from_mail_parser(
        msg: &'hdr mail_parser::Message<'hdr>,
    ) -> Result<Self, DkimSignaturesError> {
        let mut new_self = Self {
            dkim_signatures: vec![],
        };

        new_self.dkim_signatures = msg
            .header_values("DKIM-Signature")
            .into_iter()
            .map(|mh| mh.try_into().unwrap())
            .collect();

        Ok(new_self)
    }
}

#[cfg(test)]
mod test {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use insta::assert_debug_snapshot;
    #[allow(unused_imports)]
    use rstest::rstest;
    #[allow(unused_imports)]
    use std::{fs::File, io::Read, path::PathBuf};

    #[allow(dead_code)]
    fn load_test_data(file_location: &str) -> Vec<u8> {
        let mut file = File::open(file_location).unwrap();
        let mut data: Vec<u8> = vec![];
        file.read_to_end(&mut data).unwrap();
        data
    }

    #[rstest]
    #[cfg(feature = "mail_parser")]
    fn from_mail_parser(#[files("test_data/rfc8601_b*.txt")] file_path: PathBuf) {
        let new_snapshot_path = file_path.with_extension("snap");

        insta::with_settings!({snapshot_path => new_snapshot_path}, {
            insta::allow_duplicates! {
                let data = load_test_data(file_path.to_str().unwrap());

                let parser = mail_parser::MessageParser::default();

                let parsed = parser.parse(&data).unwrap();

                let status = MessageAuthStatus::alloc_from_mail_parser(&parsed);
                assert_debug_snapshot!(&status);
            }
        });
    }
}
