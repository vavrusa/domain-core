//! Record data from [RFC 1035].
//!
//! This RFC defines the initial set of record types.
//!
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use std::{fmt, ops};
use std::cmp::Ordering;
use std::net::Ipv4Addr;
use std::str::FromStr;
use bytes::{BufMut, Bytes, BytesMut};
use crate::cmp::CanonicalOrd;
use crate::compose::{Compose, Compress, Compressor};
use crate::iana::Rtype;
use crate::charstr::CharStr;
use crate::master::scan::{CharSource, ScanError, Scan, Scanner};
use crate::name::{ParsedDname, ToDname};
use crate::parse::{
    ParseAll, ParseAllError, ParseOpenError, Parse, Parser, ShortBuf
};
use crate::serial::Serial;
use super::RtypeRecordData;


//------------ dname_type! --------------------------------------------------

/// A macro for implementing a record data type with a single domain name.
///
/// Implements some basic methods plus the `RecordData`, `FlatRecordData`,
/// and `Display` traits.
#[macro_export]
macro_rules! dname_type {
    ($(#[$attr:meta])* ( $target:ident, $rtype:ident, $field:ident ) ) => {
        $(#[$attr])*
        #[derive(Clone, Debug, Hash)]
        pub struct $target<N> {
            $field: N
        }

        impl<N> $target<N> {
            pub fn new($field: N) -> Self {
                $target { $field: $field }
            }

            pub fn $field(&self) -> &N {
                &self.$field
            }
        }

        //--- From and FromStr

        impl<N> From<N> for $target<N> {
            fn from(name: N) -> Self {
                Self::new(name)
            }
        }

        impl<N: FromStr> FromStr for $target<N> {
            type Err = N::Err;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                N::from_str(s).map(Self::new)
            }
        }


        //--- PartialEq and Eq

        impl<N: PartialEq<NN>, NN> PartialEq<$target<NN>> for $target<N> {
            fn eq(&self, other: &$target<NN>) -> bool {
                self.$field.eq(&other.$field)
            }
        }

        impl<N: Eq> Eq for $target<N> { }


        //--- PartialOrd, Ord, and CanonicalOrd

        impl<N: PartialOrd<NN>, NN> PartialOrd<$target<NN>> for $target<N> {
            fn partial_cmp(&self, other: &$target<NN>) -> Option<Ordering> {
                self.$field.partial_cmp(&other.$field)
            }
        }

        impl<N: Ord> Ord for $target<N> {
            fn cmp(&self, other: &Self) -> Ordering {
                self.$field.cmp(&other.$field)
            }
        }

        impl<N: ToDname, NN: ToDname> CanonicalOrd<$target<NN>> for $target<N> {
            fn canonical_cmp(&self, other: &$target<NN>) -> Ordering {
                self.$field.lowercase_composed_cmp(&other.$field)
            }
        }


        //--- Parse, ParseAll, Compose, and Compress

        impl Parse for $target<ParsedDname> {
            type Err = <ParsedDname as Parse>::Err;

            fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
                ParsedDname::parse(parser).map(Self::new)
            }

            fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
                ParsedDname::skip(parser).map_err(Into::into)
            }
        }

        impl ParseAll for $target<ParsedDname> {
            type Err = <ParsedDname as ParseAll>::Err;

            fn parse_all(parser: &mut Parser, len: usize)
                         -> Result<Self, Self::Err> {
                ParsedDname::parse_all(parser, len).map(Self::new)
            }
        }

        impl<N: Compose> Compose for $target<N> {
            fn compose_len(&self) -> usize {
                self.$field.compose_len()
            }
        
            fn compose<B: BufMut>(&self, buf: &mut B) {
                self.$field.compose(buf)
            }

            fn compose_canonical<B: BufMut>(&self, buf: &mut B) {
                self.$field.compose_canonical(buf)
            }
        }

        impl<N: Compress> Compress for $target<N> {
            fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
                self.$field.compress(buf)
            }
        }


        //--- Scan and Display

        impl<N: Scan> Scan for $target<N> {
            fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                                   -> Result<Self, ScanError> {
                N::scan(scanner).map(Self::new)
            }
        }

        impl<N: fmt::Display> fmt::Display for $target<N> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}.", self.$field)
            }
        }


        //--- RtypeRecordData

        impl<N> RtypeRecordData for $target<N> {
            const RTYPE: Rtype = Rtype::$rtype;
        }


        //--- Deref

        impl<N> ops::Deref for $target<N> {
            type Target = N;

            fn deref(&self) -> &Self::Target {
                &self.$field
            }
        }
    }
}


//------------ A ------------------------------------------------------------

/// A record data.
///
/// A records convey the IPv4 address of a host. The wire format is the 32
/// bit IPv4 address in network byte order. The master file format is the
/// usual dotted notation.
///
/// The A record type is defined in RFC 1035, section 3.4.1.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct A {
    addr: Ipv4Addr,
}

impl A {
    /// Creates a new A record data from an IPv4 address.
    pub fn new(addr: Ipv4Addr) -> A {
        A { addr }
    }

    /// Creates a new A record from the IPv4 address components.
    pub fn from_octets(a: u8, b: u8, c: u8, d: u8) -> A {
        A::new(Ipv4Addr::new(a, b, c, d))
    }

    pub fn addr(&self) -> Ipv4Addr { self.addr }
    pub fn set_addr(&mut self, addr: Ipv4Addr) { self.addr = addr }
}


//--- From and FromStr

impl From<Ipv4Addr> for A {
    fn from(addr: Ipv4Addr) -> Self {
        Self::new(addr)
    }
}

impl From<A> for Ipv4Addr {
    fn from(a: A) -> Self {
        a.addr
    }
}

impl FromStr for A {
    type Err = <Ipv4Addr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv4Addr::from_str(s).map(A::new)
    }
}


//--- CanonicalOrd

impl CanonicalOrd for A {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}


//--- Parse, ParseAll, Compose, and Compress

impl Parse for A {
    type Err = <Ipv4Addr as Parse>::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ipv4Addr::parse(parser).map(Self::new)
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        Ipv4Addr::skip(parser)?;
        Ok(())
    }
}

impl ParseAll for A {
    type Err = <Ipv4Addr as ParseAll>::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        Ipv4Addr::parse_all(parser, len).map(Self::new)
    }
}

impl Compose for A {
    fn compose_len(&self) -> usize {
        4
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.addr.compose(buf)
    }
}

impl Compress for A {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Display

impl Scan for A {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.scan_string_phrase(|res| A::from_str(&res).map_err(Into::into))
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}


//--- RtypeRecordData

impl RtypeRecordData for A {
    const RTYPE: Rtype = Rtype::A;
}


//--- Deref and DerefMut

impl ops::Deref for A {
    type Target = Ipv4Addr;

    fn deref(&self) -> &Self::Target {
        &self.addr
    }
}

impl ops::DerefMut for A {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.addr
    }
}


//--- AsRef and AsMut

impl AsRef<Ipv4Addr> for A {
    fn as_ref(&self) -> &Ipv4Addr {
        &self.addr
    }
}

impl AsMut<Ipv4Addr> for A {
    fn as_mut(&mut self) -> &mut Ipv4Addr {
        &mut self.addr
    }
}


//------------ Cname --------------------------------------------------------

dname_type! {
    /// CNAME record data.
    ///
    /// The CNAME record specifies the canonical or primary name for domain
    /// name alias.
    ///
    /// The CNAME type is defined in RFC 1035, section 3.3.1.
    (Cname, Cname, cname)
}


//------------ Hinfo --------------------------------------------------------

/// Hinfo record data.
///
/// Hinfo records are used to acquire general information about a host,
/// specifically the CPU type and operating system type.
///
/// The Hinfo type is defined in RFC 1035, section 3.3.2.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hinfo {
    cpu: CharStr,
    os: CharStr,
}

impl Hinfo {
    /// Creates a new Hinfo record data from the components.
    pub fn new(cpu: CharStr, os: CharStr) -> Self {
        Hinfo { cpu, os }
    }

    /// The CPU type of the host.
    pub fn cpu(&self) -> &CharStr {
        &self.cpu
    }

    /// The operating system type of the host.
    pub fn os(&self) -> &CharStr {
        &self.os
    }
}


//--- CanonicalCmp

impl CanonicalOrd for Hinfo {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        match self.cpu.canonical_cmp(&other.cpu) {
            Ordering::Equal => { }
            other => return other
        }
        self.os.canonical_cmp(&other.os)
    }
}


//--- Parse, Compose, and Compress

impl Parse for Hinfo {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Self::new(CharStr::parse(parser)?, CharStr::parse(parser)?))
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        CharStr::skip(parser)?;
        CharStr::skip(parser)?;
        Ok(())
    }
}

impl ParseAll for Hinfo {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize)
                    -> Result<Self, Self::Err> {
        let cpu = CharStr::parse(parser)?;
        let len = match len.checked_sub(cpu.len() + 1) {
            Some(len) => len,
            None => return Err(ParseAllError::ShortField)
        };
        let os = CharStr::parse_all(parser, len)?;
        Ok(Hinfo::new(cpu, os))
    }
}

impl Compose for Hinfo {
    fn compose_len(&self) -> usize {
        self.cpu.compose_len() + self.os.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.cpu.compose(buf);
        self.os.compose(buf);
    }
}

impl Compress for Hinfo {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Display

impl Scan for Hinfo {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        Ok(Self::new(CharStr::scan(scanner)?, CharStr::scan(scanner)?))
    }
}

impl fmt::Display for Hinfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.cpu, self.os)
    }
}


//--- RtypeRecordData

impl RtypeRecordData for Hinfo {
    const RTYPE: Rtype = Rtype::Hinfo;
}


//------------ Mb -----------------------------------------------------------

dname_type! {
    /// MB record data.
    ///
    /// The experimental MB record specifies a host that serves a mailbox.
    ///
    /// The MB record type is defined in RFC 1035, section 3.3.3.
    (Mb, Mb, madname)
}


//------------ Md -----------------------------------------------------------

dname_type! {
    /// MD record data.
    ///
    /// The MD record specifices a host which has a mail agent for
    /// the domain which should be able to deliver mail for the domain.
    /// 
    /// The MD record is obsolete. It is recommended to either reject the record
    /// or convert them into an Mx record at preference 0.
    ///
    /// The MD record type is defined in RFC 1035, section 3.3.4.
    (Md, Md, madname)
}


//------------ Mf -----------------------------------------------------------

dname_type! {
    /// MF record data.
    ///
    /// The MF record specifices a host which has a mail agent for
    /// the domain which will be accept mail for forwarding to the domain.
    /// 
    /// The MF record is obsolete. It is recommended to either reject the record
    /// or convert them into an Mx record at preference 10.
    ///
    /// The MF record type is defined in RFC 1035, section 3.3.5.
    (Mf, Mf, madname)
}


//------------ Mg -----------------------------------------------------------

dname_type! {
    /// MG record data.
    ///
    /// The MG record specifices a mailbox which is a member of the mail group
    /// specified by the domain name.
    /// 
    /// The MG record is experimental.
    ///
    /// The MG record type is defined in RFC 1035, section 3.3.6.
    (Mg, Mg, madname)
}


//------------ Minfo --------------------------------------------------------

/// Minfo record data.
///
/// The Minfo record specifies a mailbox which is responsible for the mailing
/// list or mailbox and a mailbox that receives error messages related to the
/// list or box.
///
/// The Minfo record is experimental.
///
/// The Minfo record type is defined in RFC 1035, section 3.3.7.
#[derive(Clone, Debug, Hash)]
pub struct Minfo<N=ParsedDname> {
    rmailbx: N,
    emailbx: N,
}

impl<N> Minfo<N> {
    /// Creates a new Minfo record data from the components.
    pub fn new(rmailbx: N, emailbx: N) -> Self {
        Minfo { rmailbx, emailbx }
    }

    /// The responsible mail box.
    ///
    /// The domain name specifies the mailbox which is responsible for the
    /// mailing list or mailbox. If this domain name is the root, the owner
    /// of the Minfo record is responsible for itself.
    pub fn rmailbx(&self) -> &N {
        &self.rmailbx
    }

    /// The error mail box.
    ///
    /// The domain name specifies a mailbox which is to receive error
    /// messages related to the mailing list or mailbox specified by the
    /// owner of the record. If this is the root domain name, errors should
    /// be returned to the sender of the message.
    pub fn emailbx(&self) -> &N {
        &self.emailbx
    }
}


//--- PartialEq and Eq

impl<N: PartialEq<NN>, NN> PartialEq<Minfo<NN>> for Minfo<N> {
    fn eq(&self, other: &Minfo<NN>) -> bool {
        self.rmailbx.eq(&other.rmailbx) && self.emailbx.eq(&other.emailbx)
    }
}

impl<N: Eq> Eq for Minfo<N> { }


//--- PartialOrd, Ord, and CanonicalOrd

impl<N: PartialOrd<NN>, NN> PartialOrd<Minfo<NN>> for Minfo<N> {
    fn partial_cmp(&self, other: &Minfo<NN>) -> Option<Ordering> {
        match self.rmailbx.partial_cmp(&other.rmailbx) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        self.emailbx.partial_cmp(&other.emailbx)
    }
}

impl<N: Ord> Ord for Minfo<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.rmailbx.cmp(&other.rmailbx) {
            Ordering::Equal => { }
            other => return other
        }
        self.emailbx.cmp(&other.emailbx)
    }
}

impl<N: ToDname, NN: ToDname> CanonicalOrd<Minfo<NN>> for Minfo<N> {
    fn canonical_cmp(&self, other: &Minfo<NN>) -> Ordering {
        match self.rmailbx.lowercase_composed_cmp(&other.rmailbx) {
            Ordering::Equal => { }
            other => return other
        }
        self.emailbx.lowercase_composed_cmp(&other.emailbx)
    }
}


//--- Parse, ParseAll, Compose, and Compress

impl<N: Parse> Parse for Minfo<N> {
    type Err = N::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Self::new(N::parse(parser)?, N::parse(parser)?))
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        N::skip(parser)?;
        N::skip(parser)?;
        Ok(())
    }
}

impl<N: Parse + ParseAll> ParseAll for Minfo<N>
     where <N as ParseAll>::Err: From<<N as Parse>::Err> + From<ShortBuf> {
    type Err = <N as ParseAll>::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let pos = parser.pos();
        let rmailbx = N::parse(parser)?;
        let rlen = parser.pos() - pos;
        let len = if len <= rlen {
            // Because a domain name can never be empty, we seek back to the
            // beginning and reset the length to zero.
            parser.seek(pos)?;
            0
        }
        else {
            len - rlen
        };
        let emailbx = N::parse_all(parser, len)?;
        Ok(Self::new(rmailbx, emailbx))
    }
}

impl<N: Compose> Compose for Minfo<N> {
    fn compose_len(&self) -> usize {
        self.rmailbx.compose_len() + self.emailbx.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.rmailbx.compose(buf);
        self.emailbx.compose(buf);
    }

    fn compose_canonical<B: BufMut>(&self, buf: &mut B) {
        self.rmailbx.compose_canonical(buf);
        self.emailbx.compose_canonical(buf);
    }
}

impl<N: Compress> Compress for Minfo<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        self.rmailbx.compress(buf)?;
        self.emailbx.compress(buf)
    }
}


//--- Scan and Display

impl<N: Scan> Scan for Minfo<N> {
    fn scan<C: CharSource>(scanner: &mut  Scanner<C>)
                           -> Result<Self, ScanError> {
        Ok(Self::new(N::scan(scanner)?, N::scan(scanner)?))
    }
}

impl<N: fmt::Display> fmt::Display for Minfo<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}. {}.", self.rmailbx, self.emailbx)
    }
}


//--- RecordData

impl<N> RtypeRecordData for Minfo<N> {
    const RTYPE: Rtype = Rtype::Minfo;
}


//------------ Mr -----------------------------------------------------------

dname_type! {
    /// MR record data.
    ///
    /// The MR record specifices a mailbox which is the proper rename of the
    /// specified mailbox.
    /// 
    /// The MR record is experimental.
    ///
    /// The MR record type is defined in RFC 1035, section 3.3.8.
    (Mr, Mr, newname)
}


//------------ Mx -----------------------------------------------------------

/// Mx record data.
///
/// The Mx record specifies a host willing to serve as a mail exchange for
/// the owner name.
///
/// The Mx record type is defined in RFC 1035, section 3.3.9.
#[derive(Clone, Debug, Hash)]
pub struct Mx<N=ParsedDname> {
    preference: u16,
    exchange: N,
}

impl<N> Mx<N> {
    /// Creates a new Mx record data from the components.
    pub fn new(preference: u16, exchange: N) -> Self {
        Mx { preference, exchange }
    }

    /// The preference for this record.
    ///
    /// Defines an order if there are several Mx records for the same owner.
    /// Lower values are preferred.
    pub fn preference(&self) -> u16 {
        self.preference
    }

    /// The name of the host that is the exchange.
    pub fn exchange(&self) -> &N {
        &self.exchange
    }
}


//--- PartialEq and Eq

impl<N: PartialEq<NN>, NN> PartialEq<Mx<NN>> for Mx<N> {
    fn eq(&self, other: &Mx<NN>) -> bool {
        self.preference == other.preference && self.exchange == other.exchange
    }
}

impl<N: Eq> Eq for Mx<N> { }


//--- PartialOrd, Ord, and CanonicalOrd

impl<N: PartialOrd<NN>, NN> PartialOrd<Mx<NN>> for Mx<N> {
    fn partial_cmp(&self, other: &Mx<NN>) -> Option<Ordering> {
        match self.preference.partial_cmp(&other.preference) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        self.exchange.partial_cmp(&other.exchange)
    }
}

impl<N: Ord> Ord for Mx<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.preference.cmp(&other.preference) {
            Ordering::Equal => { }
            other => return other
        }
        self.exchange.cmp(&other.exchange)
    }
}

impl<N: ToDname, NN: ToDname> CanonicalOrd<Mx<NN>> for Mx<N> {
    fn canonical_cmp(&self, other: &Mx<NN>) -> Ordering {
        match self.preference.cmp(&other.preference) {
            Ordering::Equal => { }
            other => return other
        }
        self.exchange.lowercase_composed_cmp(&other.exchange)
    }
}


//--- Parse, ParseAll, Compose, Compress

impl<N: Parse> Parse for Mx<N>
     where N::Err: From<ShortBuf> {
    type Err = N::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Self::new(u16::parse(parser)?, N::parse(parser)?))
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        u16::skip(parser)?;
        N::skip(parser)
    }
}

impl<N: ParseAll> ParseAll for Mx<N>
     where N::Err: From<ParseOpenError> + From<ShortBuf> {
    type Err = N::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 3 {
            return Err(ParseOpenError::ShortField.into())
        }
        Ok(Self::new(u16::parse(parser)?, N::parse_all(parser, len - 2)?))
    }
}

impl<N: Compose> Compose for Mx<N> {
    fn compose_len(&self) -> usize {
        self.exchange.compose_len() + 2
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.preference.compose(buf);
        self.exchange.compose(buf);
    }

    fn compose_canonical<B: BufMut>(&self, buf: &mut B) {
        self.preference.compose(buf);
        self.exchange.compose_canonical(buf);
    }
}

impl<N: Compress> Compress for Mx<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(&self.preference)?;
        self.exchange.compress(buf)
    }
}


//--- Scan and Display

impl<N: Scan> Scan for Mx<N> {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        Ok(Self::new(u16::scan(scanner)?, N::scan(scanner)?))
    }
}

impl<N: fmt::Display> fmt::Display for Mx<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}.", self.preference, self.exchange)
    }
}


//--- RtypeRecordData

impl<N> RtypeRecordData for Mx<N> {
    const RTYPE: Rtype = Rtype::Mx;
}


//------------ Ns -----------------------------------------------------------

dname_type! {
    /// NS record data.
    ///
    /// NS records specify hosts that are authoritative for a class and domain.
    ///
    /// The NS record type is defined in RFC 1035, section 3.3.11.
    (Ns, Ns, nsdname)
}


//------------ Null ---------------------------------------------------------

/// Null record data.
///
/// Null records can contain whatever data. They are experimental and not
/// allowed in master files.
///
/// The Null record type is defined in RFC 1035, section 3.3.10.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Null {
    data: Bytes,
}

impl Null {
    /// Creates new, empty owned Null record data.
    pub fn new(data: Bytes) -> Self {
        Null { data }
    }

    /// The raw content of the record.
    pub fn data(&self) -> &Bytes {
        &self.data
    }
}


//--- From

impl From<Bytes> for Null {
    fn from(data: Bytes) -> Self {
        Self::new(data)
    }
}


//--- CanonicalOrd

impl CanonicalOrd for Null {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}


//--- ParseAll, Compose, and Compress

impl ParseAll for Null {
    type Err = ShortBuf;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        parser.parse_bytes(len).map(Self::new)
    }
}

impl Compose for Null {
    fn compose_len(&self) -> usize {
        self.data.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.data.as_ref())
    }
}

impl Compress for Null {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- RtypeRecordData

impl RtypeRecordData for Null {
    const RTYPE: Rtype = Rtype::Null;
}


//--- Deref

impl ops::Deref for Null {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}


//--- AsRef

impl AsRef<Bytes> for Null {
    fn as_ref(&self) -> &Bytes {
        &self.data
    }
}

impl AsRef<[u8]> for Null {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}


//--- Display

impl fmt::Display for Null {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\\# {}", self.data().len())?;
        for ch in self.data().iter() {
            write!(f, " {:02x}", ch)?;
        }
        Ok(())
    }
}


//------------ Ptr ----------------------------------------------------------

dname_type! {
    /// PTR record data.
    ///
    /// PRT records are used in special domains to point to some other location
    /// in the domain space.
    ///
    /// The PTR record type is defined in RFC 1035, section 3.3.12.
    (Ptr, Ptr, ptrdname)
}

impl<N> Ptr<N> {
    pub fn into_ptrdname(self) -> N {
        self.ptrdname
    }
}


//------------ Soa ----------------------------------------------------------

/// Soa record data.
///
/// Soa records mark the top of a zone and contain information pertinent to
/// name server maintenance operations.
///
/// The Soa record type is defined in RFC 1035, section 3.3.13.
#[derive(Clone, Debug, Hash)]
pub struct Soa<N=ParsedDname> {
    mname: N,
    rname: N,
    serial: Serial,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum:u32 
}

impl<N> Soa<N> {
    /// Creates new Soa record data from content.
    pub fn new(mname: N, rname: N, serial: Serial,
               refresh: u32, retry: u32, expire: u32, minimum: u32) -> Self {
        Soa { mname, rname, serial, refresh, retry, expire, minimum }
    }

    /// The primary name server for the zone.
    pub fn mname(&self) -> &N {
        &self.mname
    }

    /// The mailbox for the person responsible for this zone.
    pub fn rname(&self) -> &N {
        &self.rname
    }

    /// The serial number of the original copy of the zone.
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// The time interval in seconds before the zone should be refreshed.
    pub fn refresh(&self) -> u32 {
        self.refresh
    }

    /// The time in seconds before a failed refresh is retried.
    pub fn retry(&self) -> u32 {
        self.retry
    }

    /// The upper limit of time in seconds the zone is authoritative.
    pub fn expire(&self) -> u32 {
        self.expire
    }

    /// The minimum TTL to be exported with any RR from this zone.
    pub fn minimum(&self) -> u32 {
        self.minimum
    }
}


//--- PartialEq and Eq

impl<N: PartialEq<NN>, NN> PartialEq<Soa<NN>> for Soa<N> {
    fn eq(&self, other: &Soa<NN>) -> bool {
        self.mname == other.mname && self.rname == other.rname
        && self.serial == other.serial && self.refresh == other.refresh
        && self.retry == other.retry && self.expire == other.expire
        && self.minimum == other.minimum
    }
}

impl<N: Eq> Eq for Soa<N> { }


//--- PartialOrd, Ord, and CanonicalOrd

impl<N: PartialOrd<NN>, NN> PartialOrd<Soa<NN>> for Soa<N> {
    fn partial_cmp(&self, other: &Soa<NN>) -> Option<Ordering> {
        match self.mname.partial_cmp(&other.mname) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.rname.partial_cmp(&other.rname) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match u32::from(self.serial).partial_cmp(&u32::from(other.serial)) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.refresh.partial_cmp(&other.refresh) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.retry.partial_cmp(&other.retry) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.expire.partial_cmp(&other.expire) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        self.minimum.partial_cmp(&other.minimum)
    }
}

impl<N: Ord> Ord for Soa<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.mname.cmp(&other.mname) {
            Ordering::Equal => { }
            other => return other
        }
        match self.rname.cmp(&other.rname) {
            Ordering::Equal => { }
            other => return other
        }
        match u32::from(self.serial).cmp(&u32::from(other.serial)) {
            Ordering::Equal => { }
            other => return other
        }
        match self.refresh.cmp(&other.refresh) {
            Ordering::Equal => { }
            other => return other
        }
        match self.retry.cmp(&other.retry) {
            Ordering::Equal => { }
            other => return other
        }
        match self.expire.cmp(&other.expire) {
            Ordering::Equal => { }
            other => return other
        }
        self.minimum.cmp(&other.minimum)
    }
}

impl<N: ToDname, NN: ToDname> CanonicalOrd<Soa<NN>> for Soa<N> {
    fn canonical_cmp(&self, other: &Soa<NN>) -> Ordering {
        match self.mname.lowercase_composed_cmp(&other.mname) {
            Ordering::Equal => { }
            other => return other
        }
        match self.rname.lowercase_composed_cmp(&other.rname) {
            Ordering::Equal => { }
            other => return other
        }
        match self.serial.canonical_cmp(&other.serial) {
            Ordering::Equal => { }
            other => return other
        }
        match self.refresh.cmp(&other.refresh) {
            Ordering::Equal => { }
            other => return other
        }
        match self.retry.cmp(&other.retry) {
            Ordering::Equal => { }
            other => return other
        }
        match self.expire.cmp(&other.expire) {
            Ordering::Equal => { }
            other => return other
        }
        self.minimum.cmp(&other.minimum)
    }
}


//--- Parse, ParseAll, Compose, and Compress

impl<N: Parse> Parse for Soa<N> where N::Err: From<ShortBuf> {
    type Err = N::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Self::new(N::parse(parser)?, N::parse(parser)?,
                     Serial::parse(parser)?, u32::parse(parser)?,
                     u32::parse(parser)?, u32::parse(parser)?,
                     u32::parse(parser)?))
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        N::skip(parser)?;
        N::skip(parser)?;
        Serial::skip(parser)?;
        u32::skip(parser)?;
        u32::skip(parser)?;
        u32::skip(parser)?;
        u32::skip(parser)?;
        Ok(())
    }
}

impl<N: ParseAll + Parse> ParseAll for Soa<N>
        where <N as ParseAll>::Err: From<<N as Parse>::Err>,
              <N as ParseAll>::Err: From<ParseAllError>,
              <N as Parse>::Err: From<ShortBuf> {
    type Err = <N as ParseAll>::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let mut tmp = parser.clone();
        let res = <Self as Parse>::parse(&mut tmp)?;
        if tmp.pos() - parser.pos() < len {
            Err(ParseAllError::TrailingData.into())
        }
        else if tmp.pos() - parser.pos() > len {
            Err(ParseAllError::ShortField.into())
        }
        else {
            parser.advance(len)?;
            Ok(res)
        }
    }
}

impl<N: Compose> Compose for Soa<N> {
    fn compose_len(&self) -> usize {
        self.mname.compose_len() + self.rname.compose_len() + (5 * 4)
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.mname.compose(buf);
        self.rname.compose(buf);
        self.serial.compose(buf);
        self.refresh.compose(buf);
        self.retry.compose(buf);
        self.expire.compose(buf);
        self.minimum.compose(buf);
    }

    fn compose_canonical<B: BufMut>(&self, buf: &mut B) {
        self.mname.compose_canonical(buf);
        self.rname.compose_canonical(buf);
        self.serial.compose(buf);
        self.refresh.compose(buf);
        self.retry.compose(buf);
        self.expire.compose(buf);
        self.minimum.compose(buf);
    }
}

impl<N: Compress> Compress for Soa<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        self.mname.compress(buf)?;
        self.rname.compress(buf)?;
        buf.compose(&self.serial)?;
        buf.compose(&self.refresh)?;
        buf.compose(&self.retry)?;
        buf.compose(&self.expire)?;
        buf.compose(&self.minimum)
    }
}


//--- Scan and Display

impl<N: Scan> Scan for Soa<N> {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        Ok(Self::new(N::scan(scanner)?, N::scan(scanner)?,
                     Serial::scan(scanner)?, u32::scan(scanner)?,
                     u32::scan(scanner)?, u32::scan(scanner)?,
                     u32::scan(scanner)?))
    }
}

impl<N: fmt::Display> fmt::Display for Soa<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}. {}. {} {} {} {} {}",
               self.mname, self.rname, self.serial, self.refresh, self.retry,
               self.expire, self.minimum)
    }
}


//--- RecordData

impl<N> RtypeRecordData for Soa<N> {
    const RTYPE: Rtype = Rtype::Soa;
}


//------------ Txt ----------------------------------------------------------

/// Txt record data.
///
/// Txt records hold descriptive text.
///
/// The Txt record type is defined in RFC 1035, section 3.3.14.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Txt {
    text: Bytes,
}

impl Txt {
    /// Creates a new Txt record from a single character string.
    pub fn new(text: CharStr) -> Self {
        Txt { text: text.into_bytes() }
    }

    /// Returns an iterator over the text items.
    ///
    /// The Txt format contains one or more length-delimited byte strings.
    /// This method returns an iterator over each of them.
    pub fn iter(&self) -> TxtIter {
        TxtIter::new(self.text.clone())
    }

    /// Returns the text content.
    ///
    /// If the data is only one single character string, returns a simple
    /// clone of the slice with the data. If there are several character
    /// strings, their content will be copied together into one single,
    /// newly allocated bytes value.
    ///
    /// Access to the individual character strings is possible via iteration.
    pub fn text(&self) -> Bytes {
        if self.text[0] as usize == self.text.len() + 1 {
            self.text.slice_from(1)
        }
        else {
            // Capacity will be a few bytes too much. Probably better than
            // re-allocating.
            let mut res = BytesMut::with_capacity(self.text.len());
            for item in self.iter() {
                res.put_slice(item.as_ref());
            }
            res.freeze()
        }
    }
}


//--- IntoIterator

impl IntoIterator for Txt {
    type Item = CharStr;
    type IntoIter = TxtIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a Txt {
    type Item = CharStr;
    type IntoIter = TxtIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- CanonicalOrd

impl CanonicalOrd for Txt {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}


//--- ParseAll, Compose, and Compress

impl ParseAll for Txt {
    type Err = ParseOpenError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let text = parser.parse_bytes(len)?;
        let mut tmp = Parser::from_bytes(text.clone());
        while tmp.remaining() > 0 {
            CharStr::skip(&mut tmp).map_err(|_| ParseOpenError::ShortField)?
        }
        Ok(Txt { text })
    }
}

impl Compose for Txt {
    fn compose_len(&self) -> usize {
        self.text.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.text.as_ref())
    }
}

impl Compress for Txt {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Display

impl Scan for Txt {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        let first = CharStr::scan(scanner)?;
        let second = match CharStr::scan(scanner) {
            Err(_) => return Ok(Txt::new(first)),
            Ok(second) => second,
        };
        let mut text = first.into_bytes();
        text.extend_from_slice(second.as_ref());
        while let Ok(some) = CharStr::scan(scanner) {
            text.extend_from_slice(some.as_ref());
        }
        Ok(Txt { text })
    }
}

impl fmt::Display for Txt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut items = self.iter();
        match items.next() {
            Some(item) => item.fmt(f)?,
            None => return Ok(())
        }
        for item in items {
            write!(f, " {}", item)?;
        }
        Ok(())
    }
}


//--- RecordData

impl RtypeRecordData for Txt {
    const RTYPE: Rtype = Rtype::Txt;
}


//------------ TxtIter -------------------------------------------------------

/// An iterator over the character strings of a Txt record.
#[derive(Clone, Debug)]
pub struct TxtIter {
    parser: Parser,
}

impl TxtIter {
    fn new(text: Bytes)-> Self {
        TxtIter { parser: Parser::from_bytes(text) }
    }
}

impl Iterator for TxtIter {
    type Item = CharStr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            None
        }
        else {
            Some(CharStr::parse(&mut self.parser).unwrap())
        }
    }
}

//------------ parsed sub-module ---------------------------------------------

pub mod parsed {
    use crate::name::ParsedDname;

    pub use super::A;
    pub type Cname = super::Cname<ParsedDname>;
    pub use super::Hinfo;
    pub type Mb = super::Mb<ParsedDname>;
    pub type Md = super::Md<ParsedDname>;
    pub type Mf = super::Mf<ParsedDname>;
    pub type Mg = super::Mg<ParsedDname>;
    pub type Minfo = super::Minfo<ParsedDname>;
    pub type Mr = super::Mr<ParsedDname>;
    pub type Mx = super::Mx<ParsedDname>;
    pub type Ns = super::Ns<ParsedDname>;
    pub use super::Null;
    pub type Ptr = super::Ptr<ParsedDname>;
    pub type Soa = super::Soa<ParsedDname>;
    pub use super::Txt;
}

//============ Test ==========================================================

#[cfg(test)]
mod test {
}