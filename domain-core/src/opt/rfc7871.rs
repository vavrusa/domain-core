//! EDNS Options from RFC 7871

use std::error;
use std::net::IpAddr;
use bytes::BufMut;
use derive_more::Display;
use crate::compose::Compose;
use crate::iana::OptionCode;
use crate::message_builder::OptBuilder;
use crate::parse::{ParseAll, Parser, ShortBuf};
use super::CodeOptData;

// Option fixed header length
const HEADER_LEN: usize = 4;

//------------ ClientSubnet --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClientSubnet {
    source_prefix_len: u8,
    scope_prefix_len: u8,
    addr: IpAddr,
}


impl ClientSubnet {
    pub fn new(source_prefix_len: u8, scope_prefix_len: u8, addr: IpAddr)
               -> ClientSubnet {
        ClientSubnet { source_prefix_len, scope_prefix_len, addr }
    }

    pub fn push(builder: &mut OptBuilder, source_prefix_len: u8,
                scope_prefix_len: u8, addr: IpAddr) -> Result<(), ShortBuf> {
        builder.push(&Self::new(source_prefix_len, scope_prefix_len, addr))
    }

    pub fn source_prefix_len(&self) -> u8 { self.source_prefix_len }
    pub fn scope_prefix_len(&self) -> u8 { self.scope_prefix_len }
    pub fn addr(&self) -> IpAddr { self.addr }
}


//--- ParseAll and Compose


impl ParseAll for ClientSubnet {
    type Err = OptionParseError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let family = parser.parse_u16()?;
        let source_prefix_len = parser.parse_u8()?;
        let scope_prefix_len = parser.parse_u8()?;

        // https://tools.ietf.org/html/rfc7871#section-6
        //
        // o  ADDRESS, variable number of octets, contains either an IPv4 or
        //    IPv6 address, depending on FAMILY, which MUST be truncated to the
        //    number of bits indicated by the SOURCE PREFIX-LENGTH field,
        //    padding with 0 bits to pad to the end of the last octet needed.
        let prefix_bytes = prefix_bytes(source_prefix_len as usize);
        if prefix_bytes + HEADER_LEN > len {
            return Err(OptionParseError::ShortBuf);
        }

        let addr = match family {
            1 => {
                let mut buf = [0; 4];
                if prefix_bytes > buf.len() {
                    return Err(OptionParseError::InvalidV4Length(prefix_bytes));
                }

                parser.parse_buf(&mut buf[..prefix_bytes])?;
                IpAddr::from(buf)
            }
            2 => {
                let mut buf = [0; 16];
                if prefix_bytes > buf.len() {
                    return Err(OptionParseError::InvalidV6Length(prefix_bytes));
                }

                parser.parse_buf(&mut buf[..prefix_bytes])?;
                IpAddr::from(buf)
            }
            _ => return Err(OptionParseError::InvalidFamily(family))
        };
        Ok(ClientSubnet::new(source_prefix_len, scope_prefix_len, addr))
    }
}

impl Compose for ClientSubnet {
    fn compose_len(&self) -> usize {
        let prefix_bytes = prefix_bytes(self.source_prefix_len as usize);
        HEADER_LEN + prefix_bytes
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        let prefix_bytes = prefix_bytes(self.source_prefix_len as usize);
        match self.addr {
            IpAddr::V4(addr) => {
                1u16.compose(buf);
                self.source_prefix_len.compose(buf);
                self.scope_prefix_len.compose(buf);
                buf.put_slice(&addr.octets()[..prefix_bytes]);
            }
            IpAddr::V6(addr) => {
                2u16.compose(buf);
                self.source_prefix_len.compose(buf);
                self.scope_prefix_len.compose(buf);
                buf.put_slice(&addr.octets()[..prefix_bytes]);
            }
        }
    }
}

fn prefix_bytes(bits: usize) -> usize {
    (bits + 7) / 8
}


//--- CodeOptData

impl CodeOptData for ClientSubnet {
    const CODE: OptionCode = OptionCode::ClientSubnet;
}


//------------ ClientSubnetParseError ----------------------------------------

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum OptionParseError {
    #[display(fmt="invalid family {}", _0)]
    InvalidFamily(u16),

    #[display(fmt="invalid length {} for IPv4 address", _0)]
    InvalidV4Length(usize),

    #[display(fmt="invalid length {} for IPv6 address", _0)]
    InvalidV6Length(usize),

    #[display(fmt="unexpected end of buffer")]
    ShortBuf,
}

impl error::Error for OptionParseError { }

impl From<ShortBuf> for OptionParseError {
    fn from(_: ShortBuf) -> Self {
        OptionParseError::ShortBuf
    }
}

