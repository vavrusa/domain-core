//! Resource Records and resource record data handling.
//!
//! This module defines types related to DNS resource records. The most
//! complete one is [`Record`] which contains a complete record for a certain
//! record type. [`RecordHeader`] contains the data from a record’s header,
//! the first couple of octets common to all records. Finally,
//! [`ParsedRecord`] is similar to [`Record`] but contains the record data
//! in its raw, encoded form.
//!
//! DNS resource records consist of some common data defining the domain
//! name they pertain to, their type and class, and finally record data
//! the format of which depends on the specific record type. As there are
//! currently more than eighty record types, having a giant enum for record
//! data seemed like a bad idea. Instead, resource records are generic over
//! two traits defined by this module. All types representimg resource record
//! data implement [`RecordData`]. Types that can be parsed out of messages
//! also implement [`ParseRecordData`]. This distinction is only relevant for
//! types that contain and are generic over domain names: for these, parsing
//! is only available if the names use [`ParsedDname`].
//!
//! While [`RecordData`] allows types to provide different record types for
//! different values, most types actually implement one specific record type.
//! For these types, implementing [`RtypeRecordData`] provides a shortcut to
//! implementin both [`RecordData`] and [`ParseRecordDate`] with a constant
//! record type.
//!
//! All such implementations for a specific record type shipped with the
//! domain crate are collected in the [`domain::rdata`] module.
//!
//! A type implementing the traits for any record type is available in here
//! too: [`UnknownRecordData`]. It stores the actual record data in its
//! encoded form in a bytes value.
//!
//! [`RecordData`]: trait.RecordData.html
//! [`ParseRecordData`]: trait.ParseRecordData.html
//! [`RtypeRecordData`]: trait.RtypeRecordData.html
//! [`domain::rdata`]: ../../rdata/index.html
//! [`UnknownRecordData`]: struct.UnknownRecordData.html
//! [`Record`]: struct.Record.html
//! [`RecordHeader`]: struct.RecordHeader.html
//! [`ParsedRecord`]: struct.ParsedRecord.html

use std::{error, fmt};
use std::cmp::Ordering;
use bytes::{BigEndian, BufMut, ByteOrder};
use derive_more::Display;
use crate::cmp::CanonicalOrd;
use crate::compose::{Compose, Compress, Compressor};
use crate::iana::{Class, Rtype};
use crate::name::{ParsedDname, ParsedDnameError, ToDname};
use crate::parse::{Parse, Parser, ShortBuf};
use crate::rdata::{ParseRecordData, RecordData};


//------------ Record --------------------------------------------------------

/// A DNS resource record.
///
/// All information available through the DNS is stored in resource records.
/// They have a three part key of a domain name, resource record type, and
/// class. Data is arranged in a tree which is navigated using the domain
/// name. Each node in the tree carries a label, starting with the root
/// label as the top-most node. The tree is traversed by stepping through the
/// name from right to left, finding a child node carring the label of each
/// step. The domain name resulting from this traversal is part of the
/// record itself. It is called the *owner* of the record.
///
/// The record type describes the kind of data the record holds, such as IP
/// addresses. The class, finally, describes which sort of network the
/// information is for since DNS was originally intended to be used for
/// networks other than the Internet as well. In practice, the only relevant
/// class is IN, the Internet. Note that each class has its own tree of nodes.
///
/// The payload of a resource record is its data. Its purpose, meaning, and
/// format is determined by the record type (technically, also its class).
/// For each unique three-part key there can be multiple resource records.
/// All these records for the same key are called *resource record sets,*
/// most often shortened to ‘RRset.’
///
/// There is one more piece of data: the TTL or time to live. This value
/// says how long a record remains valid before it should be refreshed from
/// its original source, given in seconds. The TTL is used to add caching
/// facilities to the DNS.
///
/// Values of the `Record` type represent one single resource record. Since
/// there are currently more than eighty record types—see [`Rtype`] for a
/// complete list—, the type is generic over a trait for record data. This
/// trait holds both the record type value and the record data as they are
/// inseparably entwined.
///
/// Because a record’s owner is a domain name, the `Record` type is
/// additionally generic over the domain name type is for it. 
///
/// There is three ways to create a record value. First, you can make one
/// yourself using the [`new`] function. It will neatly take care of all
/// the generics through type inference. Secondly, you can parse a record
/// from an existing message. [`Message`] and its friends provide a way to
/// do that; see there for all the details. Finally, you can scan a record
/// from master data (aka zonefiles). See the [`domain::master`] module for
/// that.
///
/// Records can be place into DNS messages by using a [`MessageBuilder`]. In
/// order to make adding records easier, `Record` implements the `From` trait
/// for two kinds of tuples: A four-tuple of owner, class, time-to-live value,
/// and record data and a triple leaving out the class and assuming it to be
/// `Class::In`.
///
/// [`new`]: #method.new
/// [`Message`]: ../message/struct.Message.html
/// [`MessageBuilder`]: ../message_builder/struct.MessageBuilder.html
/// [`Rtype`]: ../../iana/enum.Rtype.html
/// [`domain::master`]: ../../master/index.html
#[derive(Clone, Debug)]
pub struct Record<N, D> {
    /// The owner of the record.
    owner: N,

    /// The class of the record.
    class: Class,

    /// The time-to-live value of the record.
    ttl: u32,

    /// The record data. The value also specifies the record’s type.
    data: D
}


/// # Creation and Element Access
///
impl<N, D> Record<N, D> {
    /// Creates a new record from its parts.
    pub fn new(owner: N, class: Class, ttl: u32, data: D) -> Self {
        Record { owner, class, ttl, data }
    }

    /// Creates a new record from a compatible record.
    ///
    /// This function only exists because the equivalent `From` implementation
    /// is currently not possible,
    pub fn from_record<NN, DD>(record: Record<NN, DD>) -> Self
    where N: From<NN>, D: From<DD> {
        Self::new(
            record.owner.into(),
            record.class,
            record.ttl,
            record.data.into()
        )
    }

    /// Returns a reference to owner domain name.
    ///
    /// The owner of a record is the domain name that specifies the node in
    /// the DNS tree this record belongs to.
    pub fn owner(&self) -> &N {
        &self.owner
    }

    /// Returns the record type.
    pub fn rtype(&self) -> Rtype
    where D: RecordData {
        self.data.rtype()
    }

    /// Returns the record class.
    pub fn class(&self) -> Class {
        self.class
    }

    /// Sets the record’s class.
    pub fn set_class(&mut self, class: Class) {
        self.class = class
    }

    /// Returns the record’s time-to-live.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Sets the record’s time-to-live.
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl
    }

    /// Return a reference to the record data.
    pub fn data(&self) -> &D {
        &self.data
    }

    /// Returns a mutable reference to the record data.
    pub fn data_mut(&mut self) -> &mut D {
        &mut self.data
    }

    /// Trades the record for its record data.
    pub fn into_data(self) -> D {
        self.data
    }
}


//--- From

impl<N, D> From<(N, Class, u32, D)> for Record<N, D> {
    fn from((owner, class, ttl, data): (N, Class, u32, D)) -> Self {
        Self::new(owner, class, ttl, data)
    }
}

impl<N, D> From<(N, u32, D)> for Record<N, D> {
    fn from((owner, ttl, data): (N, u32, D)) -> Self {
        Self::new(owner, Class::In, ttl, data)
    }
}


//--- PartialEq and Eq

impl<N, NN, D, DD> PartialEq<Record<NN, DD>> for Record<N, D>
where N: PartialEq<NN>, D: RecordData + PartialEq<DD>, DD: RecordData {
    fn eq(&self, other: &Record<NN, DD>) -> bool {
        self.owner == other.owner
        && self.class == other.class
        && self.data == other.data
    }
}

impl<N: Eq, D: RecordData + Eq> Eq for Record<N, D> { }


//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN, D, DD> PartialOrd<Record<NN, DD>> for Record<N, D>
where N: PartialOrd<NN>, D: RecordData + PartialOrd<DD>, DD: RecordData {
    fn partial_cmp(&self, other: &Record<NN, DD>) -> Option<Ordering> {
        match self.owner.partial_cmp(&other.owner) {
            Some(Ordering::Equal) => { }
            res => return res
        }
        match self.class.partial_cmp(&other.class) {
            Some(Ordering::Equal) => { }
            res => return res
        }
        self.data.partial_cmp(&other.data)
    }
}

impl<N, D> Ord for Record<N, D>
where N: Ord, D: RecordData + Ord {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.owner.cmp(&other.owner) {
            Ordering::Equal => { }
            res => return res
        }
        match self.class.cmp(&other.class) {
            Ordering::Equal => { }
            res => return res
        }
        self.data.cmp(&other.data)
    }
}

impl<N, NN, D, DD> CanonicalOrd<Record<NN, DD>> for Record<N, D>
where N: ToDname, NN: ToDname, D: RecordData + CanonicalOrd<DD>, DD: RecordData {
    fn canonical_cmp(&self, other: &Record<NN, DD>) -> Ordering {
        // This sort order will keep all records of a zone together. Ie.,
        // all the records with the same zone and ending in a given name
        // form one sequence.
        match self.class.cmp(&other.class) {
            Ordering::Equal => { }
            res => return res
        }
        match self.owner.name_cmp(&other.owner) {
            Ordering::Equal => { }
            res => return res
        }
        match self.rtype().cmp(&other.rtype()) {
            Ordering::Equal => { }
            res => return res
        }
        self.data.canonical_cmp(&other.data)
    }
}


//--- Parsable, Compose, and Compressor

impl<D: ParseRecordData> Parse for Option<Record<ParsedDname, D>> {
    type Err = RecordParseError<ParsedDnameError, D::Err>;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        let header = match RecordHeader::parse(parser) {
            Ok(header) => header,
            Err(err) => return Err(RecordParseError::Name(err)),
        };
        match D::parse_data(header.rtype(), parser, header.rdlen() as usize) {
            Ok(Some(data)) => {
                Ok(Some(header.into_record(data)))
            }
            Ok(None) => {
                parser.advance(header.rdlen() as usize)?;
                Ok(None)
            }
            Err(err) => {
                Err(RecordParseError::Data(err))
            }
        }
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        ParsedRecord::skip(parser)
                     .map_err(RecordParseError::Name)
    }
}

impl<N: ToDname, D: RecordData> Compose for Record<N, D> {
    fn compose_len(&self) -> usize {
        self.owner.compose_len() + self.data.compose_len() + 10
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        RecordHeader::new(
            &self.owner,
            self.data.rtype(),
            self.class, self.ttl,
            self.data.compose_len() as u16
        ).compose(buf);
        self.data.compose(buf);
    }

    fn compose_canonical<B: BufMut>(&self, buf: &mut B) {
        RecordHeader::new(
            &self.owner,
            self.data.rtype(),
            self.class, self.ttl,
            self.data.compose_len() as u16
        ).compose_canonical(buf);
        self.data.compose_canonical(buf);
    }
}

impl<N: ToDname, D: RecordData + Compress> Compress for Record<N, D> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compress_name(&self.owner)?;
        buf.compose(&self.rtype())?;
        buf.compose(&self.class)?;
        buf.compose(&self.ttl)?;
        let pos = buf.len();
        buf.compose(&0u16)?;
        self.data.compress(buf)?;
        let len = buf.len() - pos - 2;
        assert!(len <= (::std::u16::MAX as usize));
        BigEndian::write_u16(&mut buf.as_slice_mut()[pos..], len as u16);
        Ok(())
    }
}


//--- Display

impl<N, D> fmt::Display for Record<N, D>
where N: fmt::Display, D: RecordData + fmt::Display {
   fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}. {} {} {} {}",
               self.owner, self.ttl, self.class, self.data.rtype(),
               self.data)
    }
}


//------------ RecordHeader --------------------------------------------------

/// The header of a resource record.
///
/// This type encapsulates the common header of a resource record. It consists
/// of the owner, record type, class, TTL, and the length of the record data.
/// It is effectively a helper type for dealing with resource records encoded
/// in a DNS message.
///
/// See [`Record`] for more details about resource records.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordHeader<N> {
    owner: N,
    rtype: Rtype,
    class: Class,
    ttl: u32,
    rdlen: u16,
}

impl<N> RecordHeader<N> {
    /// Creates a new record header from its components.
    pub fn new(owner: N, rtype: Rtype, class: Class, ttl: u32, rdlen: u16)
               -> Self {
        RecordHeader { owner, rtype, class, ttl, rdlen }
    }
}

impl RecordHeader<ParsedDname> {
    /// Parses a record header and then skips over the data.
    ///
    /// If the function succeeds, the parser will be positioned right behind
    /// the end of the record.
    pub fn parse_and_skip(parser: &mut Parser)
                          -> Result<Self, ParsedDnameError> {
        let header = Self::parse(parser)?;
        match parser.advance(header.rdlen() as usize) {
            Ok(()) => Ok(header),
            Err(_) => Err(ShortBuf.into()),
        }
    }

    /// Parses the remainder of the record and returns it.
    ///
    /// The method assumes that the parsers is currently positioned right
    /// after the end of the record header. If the record data type `D`
    /// feels capable of parsing a record with a header of `self`, the
    /// method will parse the data and return a full `Record<D>`. Otherwise,
    /// it skips over the record data.
    #[allow(clippy::type_complexity)] // I know ...
    pub fn parse_into_record<D: ParseRecordData>(self, parser: &mut Parser)
                             -> Result<Option<Record<ParsedDname, D>>,
                                       RecordParseError<ParsedDnameError,
                                                        D::Err>> {
        let end = parser.pos() + self.rdlen as usize;
        match D::parse_data(self.rtype, parser, self.rdlen as usize)
                .map_err(RecordParseError::Data)? {
            Some(data) => Ok(Some(self.into_record(data))),
            None => {
                parser.seek(end)?;
                Ok(None)
            }
        }
    }

    /// Parses only the record length and skips over all the other fields.
    fn parse_rdlen(parser: &mut Parser) -> Result<u16, ParsedDnameError> {
        ParsedDname::skip(parser)?;
        Rtype::skip(parser)?;
        Class::skip(parser)?;
        u32::skip(parser)?;
        Ok(u16::parse(parser)?)
    }
}

impl<N: ToDname> RecordHeader<N> {
    /// Returns a reference to the owner of the record.
    pub fn owner(&self) -> &N {
        &self.owner
    }

    /// Returns the record type of the record.
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// Returns the class of the record.
    pub fn class(&self) -> Class {
        self.class
    }

    /// Returns the TTL of the record.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns the data length of the record.
    pub fn rdlen(&self) -> u16 {
        self.rdlen
    }

    /// Converts the header into an actual record.
    pub fn into_record<D: RecordData>(self, data: D) -> Record<N, D> {
        Record::new(self.owner, self.class, self.ttl, data)
    }
}


//--- Parse, Compose, and Compress

impl Parse for RecordHeader<ParsedDname> {
    type Err = ParsedDnameError;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(RecordHeader::new(
                ParsedDname::parse(parser)?,
                Rtype::parse(parser)?,
                Class::parse(parser)?,
                u32::parse(parser)?,
                parser.parse_u16()?
        ))
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        ParsedDname::skip(parser)?;
        Rtype::skip(parser)?;
        Class::skip(parser)?;
        u32::skip(parser)?;
        u16::skip(parser)?;
        Ok(())
    }
}

impl<N: Compose> Compose for RecordHeader<N> {
    fn compose_len(&self) -> usize {
        self.owner.compose_len() + 10
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.owner.compose(buf);
        self.rtype.compose(buf);
        self.class.compose(buf);
        self.ttl.compose(buf);
        self.rdlen.compose(buf);
    }

    fn compose_canonical<B: BufMut>(&self, buf: &mut B) {
        self.owner.compose_canonical(buf);
        self.rtype.compose(buf);
        self.class.compose(buf);
        self.ttl.compose(buf);
        self.rdlen.compose(buf);
    }
}

impl<N: Compress> Compress for RecordHeader<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        self.owner.compress(buf)?;
        buf.compose(&self.rtype)?;
        buf.compose(&self.class)?;
        buf.compose(&self.ttl)?;
        buf.compose(&self.rdlen)
    }
}


//------------ ParsedRecord --------------------------------------------------

/// A raw record parsed from a message.
///
/// A value of this type contains the record header and the raw record data.
/// It is mainly used as an intermediary type when turning raw message data
/// into [`Record`]s.
///
/// It allows access to the header only but can be traded for a real record
/// of a specific type of [`ParseRecordData`] (i.e., some type that knowns
/// how to parse record data) via the [`to_record`] and [`into_record`]
/// methods.
///
/// [`Record`]: struct.Record.html
/// [`ParseRecordData`]: trait.ParseRecordData.html
/// [`to_record`]: #method.to_record
/// [`into_record`]: #method.into_record
#[derive(Clone, Debug)]
pub struct ParsedRecord {
    /// The record’s header.
    header: RecordHeader<ParsedDname>,

    /// A parser positioned at the beginning of the record’s data.
    data: Parser,
}

impl ParsedRecord {
    /// Creates a new parsed record from a header and the record data.
    ///
    /// The record data is provided via a parser that is positioned at the
    /// first byte of the record data.
    pub fn new(header: RecordHeader<ParsedDname>, data: Parser) -> Self {
        ParsedRecord { header, data }
    }

    /// Returns a reference to the owner of the record.
    pub fn owner(&self) -> &ParsedDname {
        self.header.owner()
    }

    /// Returns the record type of the record.
    pub fn rtype(&self) -> Rtype {
        self.header.rtype()
    }

    /// Returns the class of the record.
    pub fn class(&self) -> Class {
        self.header.class()
    }

    /// Returns the TTL of the record.
    pub fn ttl(&self) -> u32 {
        self.header.ttl()
    }

    /// Returns the data length of the record.
    pub fn rdlen(&self) -> u16 {
        self.header.rdlen()
    }
}

impl ParsedRecord {
    /// Creates a real resource record from the parsed record.
    ///
    /// The method is generic over a type that knows how to parse record
    /// data via the [`ParseRecordData`] trait. The record data is given to
    /// this trait for parsing. If the trait feels capable of parsing this
    /// type of record (as indicated by the record type) and parsing succeeds,
    /// the method returns `Ok(Some(_))`. It returns `Ok(None)` if the trait
    /// doesn’t know how to parse this particular record type. It returns
    /// an error if parsing fails.
    ///
    /// [`ParseRecordData`]: ../rdata/trait.ParseRecordData.html
    #[allow(clippy::type_complexity)] // I know ...
    pub fn to_record<D>(
        &self
    ) -> Result<Option<Record<ParsedDname, D>>,
                RecordParseError<ParsedDnameError, D::Err>>
    where D: ParseRecordData
    {
        match D::parse_data(self.header.rtype(), &mut self.data.clone(),
                            self.header.rdlen() as usize)
                .map_err(RecordParseError::Data)? {
            Some(data) => Ok(Some(self.header.clone().into_record(data))),
            None => Ok(None)
        }
    }

    /// Trades the parsed record for a real resource record.
    ///
    /// The method is generic over a type that knows how to parse record
    /// data via the [`ParseRecordData`] trait. The record data is given to
    /// this trait for parsing. If the trait feels capable of parsing this
    /// type of record (as indicated by the record type) and parsing succeeds,
    /// the method returns `Ok(Some(_))`. It returns `Ok(None)` if the trait
    /// doesn’t know how to parse this particular record type. It returns
    /// an error if parsing fails.
    ///
    /// [`ParseRecordData`]: ../rdata/trait.ParseRecordData.html
    #[allow(clippy::type_complexity)] // I know ...
    pub fn into_record<D>(
        mut self
    ) -> Result<Option<Record<ParsedDname, D>>,
                RecordParseError<ParsedDnameError, D::Err>>
    where D: ParseRecordData
    {
        match D::parse_data(self.header.rtype(), &mut self.data,
                            self.header.rdlen() as usize)
                .map_err(RecordParseError::Data)? {
            Some(data) => Ok(Some(self.header.into_record(data))),
            None => Ok(None)
        }
    }
}


//--- Parse
//
//    No Compose or Compress because the data may contain compressed domain
//    names.

impl Parse for ParsedRecord {
    type Err = ParsedDnameError;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        let header = RecordHeader::parse(parser)?;
        let data = parser.clone();
        parser.advance(header.rdlen() as usize)?;
        Ok(Self::new(header, data))
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        let rdlen = RecordHeader::parse_rdlen(parser)?;
        parser.advance(rdlen as usize)?;
        Ok(())
    }
}


//------------ RecordParseError ----------------------------------------------

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum RecordParseError<N: error::Error, D: error::Error> {
    #[display(fmt="{}", _0)]
    Name(N),

    #[display(fmt="{}", _0)]
    Data(D),

    #[display(fmt="unexpected end of buffer")]
    ShortBuf,
}

impl<N, D> error::Error for RecordParseError<N, D>
where N: error::Error, D: error::Error { }

impl<N, D> From<ShortBuf> for RecordParseError<N, D>
where N: error::Error, D: error::Error {
    fn from(_: ShortBuf) -> Self {
        RecordParseError::ShortBuf
    }
}

