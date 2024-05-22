#![warn(
    clippy::unwrap_used,
//    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
#![doc = include_str!("../README.md")]

mod types;
pub use types::{AuthenticationResults, HostVersion, Prop};

pub mod auth;
pub mod dkim;
pub mod iprev;
pub mod spf;

mod parser;

#[derive(Debug)]
pub struct MessageAuthStatus {}

#[derive(Debug)]
pub enum Error {
    ParseNone,
}

use std::borrow::Cow;

impl<'hdr> MessageAuthStatus {
    #[cfg(feature = "mail_parse")]
    pub fn from_rfc822(msg: &'hdr [u8]) -> Result<Self, Error> {
        let parsed = match mail_parser::MessageParser::default().parse(&*msg) {
            Some(p) => p,
            None => return Err(Error::ParseNone),
        };
        let auth_results: Vec<AuthenticationResults<'_>> = parsed
            .header_values("Authentication-Results")
            .map(|mh| mh.try_into().unwrap())
            .collect();
        panic!("{:?}", auth_results);
        //panic!("{:?}", parsed.header_values("DKIM-Signature").join(","));

        Ok(Self {})
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
    #[cfg(feature = "mail_parse")]
    fn from_rfc822(#[files("test_data/rfc8601_b*.txt")] file_path: PathBuf) {
        let data = load_test_data(file_path.to_str().unwrap());
        assert_debug_snapshot!(MessageAuthStatus::from_rfc822(&*data));
    }
}
