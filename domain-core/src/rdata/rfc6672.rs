use std::{fmt, ops};
use std::cmp::Ordering;
use std::str::FromStr;
use bytes::BufMut;
use crate::cmp::CanonicalOrd;
use crate::compose::{Compose, Compress, Compressor};
use crate::iana::Rtype;
use crate::master::scan::{CharSource, ScanError, Scan, Scanner};
use crate::name::{ParsedDname, ToDname};
use crate::parse::{
    ParseAll, Parse, Parser, ShortBuf
};
use super::RtypeRecordData;

//------------ Dname --------------------------------------------------------

dname_type! {
    /// DNAME record data.
    ///
    /// The DNAME record provides redirection for a subtree of the domain
    /// name tree in the DNS.
    ///
    /// The DNAME type is defined in RFC 6672.
    (Dname, Dname, dname)
}

#[cfg(test)]
mod test {
    use crate::name::Dname;
    use crate::rdata::rfc6672;
    use core::str::FromStr;

    #[test]
    fn create_dname() {
        let name = Dname::from_str("bar.example.com").unwrap();
        let rdata = rfc6672::Dname::new(name.clone());
        assert_eq!(rdata.dname(), &name);
    }
}
