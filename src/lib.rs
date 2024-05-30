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
pub struct MessageAuthStatus<'hdr> {
    results: Vec<AuthenticationResults<'hdr>>,
}

#[derive(Debug)]
pub enum Error {
    ParseNone,
}

impl<'hdr> MessageAuthStatus<'hdr> {
    #[cfg(feature = "mail_parser")]
    pub fn from_mail_parser(msg: &'hdr mail_parser::Message<'hdr>) -> Result<Self, Error> {
        let mut new_self = Self { results: vec![] };

        new_self.results = msg
            .header_values("Authentication-Results")
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
        // set_snapshot_path

        let new_snapshot_path = file_path.with_extension("snap");
        //panic!("snapshot_path = {:?}", new_snapshot_path);

        insta::with_settings!({snapshot_path => new_snapshot_path}, {
            insta::allow_duplicates! {
                let data = load_test_data(file_path.to_str().unwrap());

                let parser = mail_parser::MessageParser::default();

                let parsed = parser.parse(&data).unwrap();

                let status = MessageAuthStatus::from_mail_parser(&parsed);
                assert_debug_snapshot!(&status);
            }
        });
    }
}
