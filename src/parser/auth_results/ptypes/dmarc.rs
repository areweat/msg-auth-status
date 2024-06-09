//! dmarc ptype and it's properties

#[derive(Debug)]
pub enum DmarcProperty<'hdr> {
    /// RFC 7489
    HeaderFrom(&'hdr str),
    /// RFC 7489
    PolicyDmarc(&'hdr str),
}

/*
#[derive(Debug)]
pub enum DmarcPtype {
    Header,
    HeaderDotFrom,
    Policy,
    PolicyDotDmarc,
}
*/
