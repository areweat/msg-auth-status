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
