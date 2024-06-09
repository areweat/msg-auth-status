//! DKIM Algorithms

/// DKIM Algorithms per IANA and RFC
#[derive(Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum DkimAlgorithm<'hdr> {
    /// Do not use
    Rsa_Sha1,
    /// Widely supported
    Rsa_Sha256,
    /// Please support this - not widely supported yet
    Ed25519_Sha256,
    /// Unknown algorithm not specified by RFC / IANA
    Unknown(&'hdr str),
}

/// Currently no error - may change in future
#[derive(Debug, PartialEq)]
pub enum DkimAlgorithmError {}

impl<'hdr> TryFrom<&'hdr str> for DkimAlgorithm<'hdr> {
    type Error = DkimAlgorithmError;

    fn try_from(algo: &'hdr str) -> Result<Self, Self::Error> {
        let ret = match algo {
            "rsa-sha1" => Self::Rsa_Sha1,
            "rsa-sha256" => Self::Rsa_Sha256,
            "ed25519-sha256" => Self::Ed25519_Sha256,
            _ => Self::Unknown(algo),
        };
        Ok(ret)
    }
}
