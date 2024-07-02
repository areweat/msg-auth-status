//! Address Specification

/// Addr-spec RFC 2822
#[derive(Clone, Debug, PartialEq)]
pub struct AddrSpec<'hdr> {
    /// Display name
    pub display_name: Option<&'hdr str>,
    /// Local part
    pub local_part: &'hdr str,
    /// Domain
    pub domain: &'hdr str,
    /// Raw
    pub raw: &'hdr str,
}
