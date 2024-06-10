//! Allocating DkimSignaturesHandler

use crate::dkim::DkimSignature;

/// TODO: Errors
#[derive(Debug, PartialEq)]
pub enum DkimSignaturesError {}

/// Allocating parsed results for DKIM-Signatures
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Default)]
pub struct DkimSignatures<'hdr> {
    /// DKIM-Signature results
    dkim_signatures: Vec<DkimSignature<'hdr>>,
}

impl<'hdr> crate::traits::ResultsVerifier for DkimSignatures<'hdr> {
    fn return_path_atleast_one_dkim_pass(&self, _selector: &str) -> bool {
        false // TODO
    }
}

impl<'hdr> DkimSignatures<'hdr> {
    /// Parse all DKIM Signatures into allocating Vec from mail_parser::Message
    #[cfg(feature = "mail_parser")]
    pub fn from_mail_parser(
        msg: &'hdr mail_parser::Message<'hdr>,
    ) -> Result<Self, DkimSignaturesError> {
        let mut new_self = Self {
            dkim_signatures: vec![],
        };

        new_self.dkim_signatures = msg
            .header_values("DKIM-Signature")
            .map(|mh| mh.try_into().unwrap())
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
                let status = DkimSignatures::from_mail_parser(&parsed_message).unwrap();
                assert_debug_snapshot!(&status);
            }
        });
    }
}
