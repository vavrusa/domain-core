//! Record data from [RFC 4034].
//!
//! This RFC defines the record types for DNSSEC.
//!
//! [RFC 4034]: https://tools.ietf.org/html/rfc4034

use bits::compose::{Compose, Compress, Compressor};
use bits::name::{Dname, DnameBytesError};
use bits::parse::{Parse, ParseAll, ParseAllError, Parser, ShortBuf};
use bits::rdata::RtypeRecordData;
use bits::record::Record;
use bits::serial::Serial;
use bytes::{BufMut, Bytes, BytesMut};
use failure::Fail;
use iana::{DigestAlg, Rtype, SecAlg};
use master::scan::{CharSource, Scan, ScanError, Scanner};
use std::{fmt, ptr};
use utils::base64;

#[cfg(feature = "dnssec")]
use bits::name::ToDname;
#[cfg(feature = "dnssec")]
use ring::{digest, signature};

//------------ AlgorithmError ------------------------------------------------

#[derive(Clone, Debug, Fail)]
pub enum AlgorithmError {
    #[fail(display = "unsupported algorithm")]
    Unsupported,
    #[fail(display = "bad signature")]
    BadSig,
}

//------------ Dnskey --------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Dnskey {
    flags: u16,
    protocol: u8,
    algorithm: SecAlg,
    public_key: Bytes,
}

impl Dnskey {
    pub fn new(flags: u16, protocol: u8, algorithm: SecAlg, public_key: Bytes) -> Self {
        Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        }
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn algorithm(&self) -> SecAlg {
        self.algorithm
    }

    pub fn public_key(&self) -> &Bytes {
        &self.public_key
    }

    /// Returns true if the key has been revoked.
    /// See [RFC 5011, Section 3](https://tools.ietf.org/html/rfc5011#section-3).
    pub fn is_revoked(&self) -> bool {
        self.flags() & 0b0000_0000_1000_0000 != 0
    }

    /// Returns true if the key has SEP (Secure Entry Point) bit set.
    /// See [RFC 4034, Section 2.1.1](https://tools.ietf.org/html/rfc4034#section-2.1.1)
    ///
    /// ```
    /// 2.1.1.  The Flags Field
    ///
    ///    This flag is only intended to be a hint to zone signing or debugging software as to the
    ///    intended use of this DNSKEY record; validators MUST NOT alter their
    ///    behavior during the signature validation process in any way based on
    ///    the setting of this bit.
    /// ```
    pub fn is_secure_entry_point(&self) -> bool {
        self.flags() & 0b0000_0000_0000_0001 != 0
    }

    /// Returns true if the key is ZSK (Zone Signing Key) bit set. If the ZSK is not set, the
    /// key MUST NOT be used to verify RRSIGs that cover RRSETs.
    /// See [RFC 4034, Section 2.1.1](https://tools.ietf.org/html/rfc4034#section-2.1.1)
    pub fn is_zsk(&self) -> bool {
        self.flags() & 0b0000_0001_0000_0000 != 0
    }

    /// Calculates a digest from DNSKEY.
    /// See [RFC 4034, Section 5.1.4](https://tools.ietf.org/html/rfc4034#section-5.1.4)
    ///
    /// ```
    /// 5.1.4.  The Digest Field
    ///   The digest is calculated by concatenating the canonical form of the
    ///   fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
    ///   and then applying the digest algorithm.
    ///
    ///     digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
    ///
    ///      "|" denotes concatenation
    ///
    ///     DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
    /// ```
    #[cfg(feature = "dnssec")]
    pub fn digest<N: ToDname>(
        &self,
        dname: &N,
        algorithm: DigestAlg,
    ) -> Result<impl AsRef<[u8]>, AlgorithmError> {
        let mut buf: Vec<u8> = Vec::new();
        dname.compose(&mut buf);
        self.compose(&mut buf);

        let mut ctx = match algorithm {
            DigestAlg::Sha1 => digest::Context::new(&digest::SHA1),
            DigestAlg::Sha256 => digest::Context::new(&digest::SHA256),
            DigestAlg::Gost => {
                return Err(AlgorithmError::Unsupported);
            }
            DigestAlg::Sha384 => digest::Context::new(&digest::SHA384),
            _ => {
                return Err(AlgorithmError::Unsupported);
            }
        };

        ctx.update(&buf);
        Ok(ctx.finish())
    }

    /// Calculates the key tag for this DNSKEY according to [RFC4034, Appendix B](https://tools.ietf.org/html/rfc4034#appendix-B).
    pub fn key_tag(&self) -> u16 {
        let mut buf = vec![];
        self.compose(&mut buf);

        let mut keytag: u32 = buf
            .iter()
            .enumerate()
            .map(|(i, v)| {
                if i & 1 != 0 {
                    u32::from(*v)
                } else {
                    u32::from(*v) << 8
                }
            })
            .sum();
        keytag += (keytag >> 16) & 0xffff;
        keytag &= 0xffff;
        keytag as u16
    }

    // Extract public key exponent and modulus.
    // See [RFC3110, Section 2](https://tools.ietf.org/html/rfc3110#section-2)
    fn rsa_exponent_modulus(&self) -> Result<(&[u8], &[u8]), AlgorithmError> {
        assert!(self.algorithm() == SecAlg::RsaSha1 || self.algorithm() == SecAlg::RsaSha256);

        let public_key = self.public_key();
        if public_key.len() <= 3 {
            // TODO: return a better error
            return Err(AlgorithmError::Unsupported);
        }

        let (pos, exp_len) = match public_key[0] {
            0 => (
                3,
                (usize::from(public_key[1]) << 8) | usize::from(public_key[2]),
            ),
            len => (1, usize::from(len)),
        };

        // Check if there's enough space for exponent and modulus.
        if public_key.len() < pos + exp_len {
            return Err(AlgorithmError::Unsupported);
        };

        Ok(public_key[pos..].split_at(exp_len))
    }
}

//--- ParseAll, Compose, and Compress

impl ParseAll for Dnskey {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 4 {
            return Err(ParseAllError::ShortField);
        }
        Ok(Self::new(
            u16::parse(parser)?,
            u8::parse(parser)?,
            SecAlg::parse(parser)?,
            Bytes::parse_all(parser, len - 4)?,
        ))
    }
}

impl Compose for Dnskey {
    fn compose_len(&self) -> usize {
        4 + self.public_key.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.flags.compose(buf);
        self.protocol.compose(buf);
        self.algorithm.compose(buf);
        self.public_key.compose(buf);
    }
}

impl Compress for Dnskey {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}

//--- Scan and Display

impl Scan for Dnskey {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>) -> Result<Self, ScanError> {
        Ok(Self::new(
            u16::scan(scanner)?,
            u8::scan(scanner)?,
            SecAlg::scan(scanner)?,
            scanner.scan_base64_phrases(Ok)?,
        ))
    }
}

impl fmt::Display for Dnskey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.flags, self.protocol, self.algorithm)?;
        base64::display(&self.public_key, f)
    }
}

//--- RecordData

impl RtypeRecordData for Dnskey {
    const RTYPE: Rtype = Rtype::Dnskey;
}

//------------ Rrsig ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Rrsig {
    type_covered: Rtype,
    algorithm: SecAlg,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer_name: Dname,
    signature: Bytes,
}

impl Rrsig {
    #[allow(too_many_arguments)] // XXX Consider changing.
    pub fn new(
        type_covered: Rtype,
        algorithm: SecAlg,
        labels: u8,
        original_ttl: u32,
        expiration: Serial,
        inception: Serial,
        key_tag: u16,
        signer_name: Dname,
        signature: Bytes,
    ) -> Self {
        Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration: expiration.into(),
            inception: inception.into(),
            key_tag,
            signer_name,
            signature,
        }
    }

    pub fn type_covered(&self) -> Rtype {
        self.type_covered
    }

    pub fn algorithm(&self) -> SecAlg {
        self.algorithm
    }

    pub fn labels(&self) -> u8 {
        self.labels
    }

    pub fn original_ttl(&self) -> u32 {
        self.original_ttl
    }

    pub fn expiration(&self) -> Serial {
        self.expiration.into()
    }

    pub fn inception(&self) -> Serial {
        self.inception.into()
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn signer_name(&self) -> &Dname {
        &self.signer_name
    }

    pub fn signature(&self) -> &Bytes {
        &self.signature
    }

    /// Compose the signed data according to [RC4035, Section 5.3.2](https://tools.ietf.org/html/rfc4035#section-5.3.2).
    ///
    /// ```
    ///    Once the RRSIG RR has met the validity requirements described in
    ///    Section 5.3.1, the validator has to reconstruct the original signed
    ///    data.  The original signed data includes RRSIG RDATA (excluding the
    ///    Signature field) and the canonical form of the RRset.  Aside from
    ///    being ordered, the canonical form of the RRset might also differ from
    ///    the received RRset due to DNS name compression, decremented TTLs, or
    ///    wildcard expansion.
    /// ```
    pub fn signed_data<N: ToDname, D: RtypeRecordData, B: BufMut>(
        &self,
        buf: &mut B,
        records: &mut [Record<N, D>],
    ) where
        D: Compose + Compress + Sized + Ord + Eq,
    {
        // signed_data = RRSIG_RDATA | RR(1) | RR(2)...  where
        //    "|" denotes concatenation
        // RRSIG_RDATA is the wire format of the RRSIG RDATA fields
        //    with the Signature field excluded and the Signer's Name
        //    in canonical form.
        self.type_covered.compose(buf);
        self.algorithm.compose(buf);
        self.labels.compose(buf);
        self.original_ttl.compose(buf);
        self.expiration.compose(buf);
        self.inception.compose(buf);
        self.key_tag.compose(buf);
        self.signer_name.compose(buf);

        // The set of all RR(i) is sorted into canonical order.
        // See https://tools.ietf.org/html/rfc4034#section-6.3
        records.sort_by(|a, b| a.data().cmp(b.data()));

        // RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
        for rr in records {
            // Handle expanded wildcards as per [RFC4035, Section 5.3.2](https://tools.ietf.org/html/rfc4035#section-5.3.2).
            let rrsig_labels = usize::from(self.labels());
            let fqdn = rr.owner();
            // Subtract the root label from count as the algorithm doesn't accomodate that.
            let mut fqdn_labels = fqdn.iter_labels().count() - 1;
            if rrsig_labels < fqdn_labels {
                // name = "*." | the rightmost rrsig_label labels of the fqdn
                b"\x01*".compose(buf);
                let mut fqdn = fqdn.to_name();
                while fqdn_labels < rrsig_labels {
                    fqdn.parent();
                    fqdn_labels -= 1;
                }
                fqdn.compose(buf);
            } else {
                fqdn.compose(buf);
            }

            rr.rtype().compose(buf);
            rr.class().compose(buf);
            self.original_ttl.compose(buf);
            let rdlen = rr.data().compose_len() as u16;
            rdlen.compose(buf);
            rr.data().compose(buf);
        }
    }

    /// Attempt to use the cryptographic signature to authenticate the signed data, and thus authenticate the RRSET.
    /// The signed data is expected to be calculated as per [RFC4035, Section 5.3.2](https://tools.ietf.org/html/rfc4035#section-5.3.2).
    ///
    /// [RFC4035, Section 5.3.2](https://tools.ietf.org/html/rfc4035#section-5.3.2):
    /// ```
    /// 5.3.3.  Checking the Signature
    ///
    ///    Once the resolver has validated the RRSIG RR as described in Section
    ///    5.3.1 and reconstructed the original signed data as described in
    ///    Section 5.3.2, the validator can attempt to use the cryptographic
    ///    signature to authenticate the signed data, and thus (finally!)
    ///    authenticate the RRset.
    ///
    ///    The Algorithm field in the RRSIG RR identifies the cryptographic
    ///    algorithm used to generate the signature.  The signature itself is
    ///    contained in the Signature field of the RRSIG RDATA, and the public
    ///    key used to verify the signature is contained in the Public Key field
    ///    of the matching DNSKEY RR(s) (found in Section 5.3.1).  [RFC4034]
    ///    provides a list of algorithm types and provides pointers to the
    ///    documents that define each algorithm's use.
    /// ```
    #[cfg(feature = "dnssec")]
    pub fn verify_signed_data(
        &self,
        dnskey: &Dnskey,
        signed_data: &Bytes,
    ) -> Result<(), AlgorithmError> {
        use untrusted::Input;

        let message = untrusted::Input::from(signed_data);
        let signature = Input::from(self.signature());

        match self.algorithm {
            SecAlg::RsaSha1 | SecAlg::RsaSha256 | SecAlg::RsaSha512 => {
                let algorithm = match self.algorithm {
                    SecAlg::RsaSha1 => &signature::RSA_PKCS1_2048_8192_SHA1,
                    SecAlg::RsaSha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    SecAlg::RsaSha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    _ => unreachable!(),
                };
                // The key isn't available in either PEM or DER, so use the direct RSA verifier.
                let (e, m) = dnskey.rsa_exponent_modulus()?;
                signature::primitive::verify_rsa(
                    algorithm,
                    (Input::from(m), Input::from(e)),
                    message,
                    signature,
                )
                .map_err(|_| AlgorithmError::BadSig)
            }
            SecAlg::EcdsaP256Sha256 | SecAlg::EcdsaP384Sha384 => {
                let algorithm = match self.algorithm {
                    SecAlg::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_FIXED,
                    SecAlg::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_FIXED,
                    _ => unreachable!(),
                };

                // Add 0x4 identifier to the ECDSA pubkey as expected by ring.
                let public_key = dnskey.public_key();
                let mut key = Vec::with_capacity(public_key.len() + 1);
                key.push(0x4);
                key.extend_from_slice(&public_key);

                signature::verify(algorithm, Input::from(&key), message, signature)
                    .map_err(|_| AlgorithmError::BadSig)
            }
            SecAlg::Ed25519 => {
                let key = dnskey.public_key();
                signature::verify(&signature::ED25519, Input::from(&key), message, signature)
                    .map_err(|_| AlgorithmError::BadSig)
            }
            _ => return Err(AlgorithmError::Unsupported),
        }
    }
}

//--- ParseAll, Compose, and Compress

impl ParseAll for Rrsig {
    type Err = DnameBytesError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let start = parser.pos();
        let type_covered = Rtype::parse(parser)?;
        let algorithm = SecAlg::parse(parser)?;
        let labels = u8::parse(parser)?;
        let original_ttl = u32::parse(parser)?;
        let expiration = Serial::parse(parser)?;
        let inception = Serial::parse(parser)?;
        let key_tag = u16::parse(parser)?;
        let signer_name = Dname::parse(parser)?;
        let len = if parser.pos() > start + len {
            return Err(ShortBuf.into());
        } else {
            len - (parser.pos() - start)
        };
        let signature = Bytes::parse_all(parser, len)?;
        Ok(Self::new(
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        ))
    }
}

impl Compose for Rrsig {
    fn compose_len(&self) -> usize {
        18 + self.signer_name.compose_len() + self.signature.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.type_covered.compose(buf);
        self.algorithm.compose(buf);
        self.labels.compose(buf);
        self.original_ttl.compose(buf);
        self.expiration.compose(buf);
        self.inception.compose(buf);
        self.key_tag.compose(buf);
        self.signer_name.compose(buf);
        self.signature.compose(buf);
    }
}

impl Compress for Rrsig {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}

//--- Scan and Display

impl Scan for Rrsig {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>) -> Result<Self, ScanError> {
        Ok(Self::new(
            Rtype::scan(scanner)?,
            SecAlg::scan(scanner)?,
            u8::scan(scanner)?,
            u32::scan(scanner)?,
            Serial::scan_rrsig(scanner)?,
            Serial::scan_rrsig(scanner)?,
            u16::scan(scanner)?,
            Dname::scan(scanner)?,
            scanner.scan_base64_phrases(Ok)?,
        ))
    }
}

impl fmt::Display for Rrsig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} ",
            self.type_covered,
            self.algorithm,
            self.labels,
            self.original_ttl,
            self.expiration,
            self.inception,
            self.key_tag,
            self.signer_name
        )?;
        base64::display(&self.signature, f)
    }
}

//--- RtypeRecordData

impl RtypeRecordData for Rrsig {
    const RTYPE: Rtype = Rtype::Rrsig;
}

//------------ Nsec ----------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Nsec<N> {
    next_name: N,
    types: RtypeBitmap,
}

impl<N> Nsec<N> {
    pub fn new(next_name: N, types: RtypeBitmap) -> Self {
        Nsec { next_name, types }
    }

    pub fn next_name(&self) -> &N {
        &self.next_name
    }

    pub fn types(&self) -> &RtypeBitmap {
        &self.types
    }
}

//--- ParseAll, Compose, and Compress

impl<N: Parse> ParseAll for Nsec<N>
where
    <N as Parse>::Err: Fail,
{
    type Err = ParseNsecError<<N as Parse>::Err>;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let start = parser.pos();
        let next_name = N::parse(parser).map_err(ParseNsecError::BadNextName)?;
        let len = if parser.pos() > start + len {
            return Err(ShortBuf.into());
        } else {
            len - (parser.pos() - start)
        };
        let types = RtypeBitmap::parse_all(parser, len)?;
        Ok(Nsec::new(next_name, types))
    }
}

impl<N: Compose> Compose for Nsec<N> {
    fn compose_len(&self) -> usize {
        self.next_name.compose_len() + self.types.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.next_name.compose(buf);
        self.types.compose(buf);
    }
}

impl<N: Compose> Compress for Nsec<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}

//--- Scan and Display

impl<N: Scan> Scan for Nsec<N> {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>) -> Result<Self, ScanError> {
        Ok(Self::new(N::scan(scanner)?, RtypeBitmap::scan(scanner)?))
    }
}

impl<N: fmt::Display> fmt::Display for Nsec<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.next_name, self.types)
    }
}

//--- RtypeRecordData

impl<N> RtypeRecordData for Nsec<N>
where
    N: Ord + Eq,
{
    const RTYPE: Rtype = Rtype::Nsec;
}

//------------ Ds -----------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ds {
    key_tag: u16,
    algorithm: SecAlg,
    digest_type: DigestAlg,
    digest: Bytes,
}

impl Ds {
    pub fn new(key_tag: u16, algorithm: SecAlg, digest_type: DigestAlg, digest: Bytes) -> Self {
        Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn algorithm(&self) -> SecAlg {
        self.algorithm
    }

    pub fn digest_type(&self) -> DigestAlg {
        self.digest_type
    }

    pub fn digest(&self) -> &Bytes {
        &self.digest
    }
}

//--- ParseAll, Compose, and Compress

impl ParseAll for Ds {
    type Err = ShortBuf;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 4 {
            return Err(ShortBuf);
        }
        Ok(Self::new(
            u16::parse(parser)?,
            SecAlg::parse(parser)?,
            DigestAlg::parse(parser)?,
            Bytes::parse_all(parser, len - 4)?,
        ))
    }
}

impl Compose for Ds {
    fn compose_len(&self) -> usize {
        self.digest.len() + 4
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.key_tag.compose(buf);
        self.algorithm.compose(buf);
        self.digest_type.compose(buf);
        self.digest.compose(buf);
    }
}

impl Compress for Ds {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}

//--- Scan and Display

impl Scan for Ds {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>) -> Result<Self, ScanError> {
        Ok(Self::new(
            u16::scan(scanner)?,
            SecAlg::scan(scanner)?,
            DigestAlg::scan(scanner)?,
            scanner.scan_hex_words(Ok)?,
        ))
    }
}

impl fmt::Display for Ds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} ",
            self.key_tag, self.algorithm, self.digest_type
        )?;
        for ch in self.digest() {
            write!(f, "{:02x}", ch)?
        }
        Ok(())
    }
}

//--- RtypeRecordData

impl RtypeRecordData for Ds {
    const RTYPE: Rtype = Rtype::Ds;
}

//------------ RtypeBitmap ---------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RtypeBitmap(Bytes);

impl RtypeBitmap {
    pub fn from_bytes(bytes: Bytes) -> Result<Self, RtypeBitmapError> {
        {
            let mut data = bytes.as_ref();
            while !data.is_empty() {
                let len = (data[1] as usize) + 2;
                if len > 34 {
                    return Err(RtypeBitmapError::BadRtypeBitmap);
                }
                if data.len() < len {
                    return Err(RtypeBitmapError::ShortBuf);
                }
                data = &data[len..];
            }
        }
        Ok(RtypeBitmap(bytes))
    }

    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn iter(&self) -> RtypeBitmapIter {
        RtypeBitmapIter::new(self.0.as_ref())
    }

    pub fn contains(&self, rtype: Rtype) -> bool {
        let (block, octet, mask) = split_rtype(rtype);
        let octet = octet + 2;
        let mut data = self.0.as_ref();
        while !data.is_empty() {
            if data[0] == block {
                return !((data[1] as usize) < octet || data[octet] & mask == 0);
            }
            data = &data[data[1] as usize..]
        }
        false
    }
}

impl AsRef<Bytes> for RtypeBitmap {
    fn as_ref(&self) -> &Bytes {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for RtypeBitmap {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

//--- IntoIterator

impl<'a> IntoIterator for &'a RtypeBitmap {
    type Item = Rtype;
    type IntoIter = RtypeBitmapIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//--- ParseAll, Compose, Compress

impl ParseAll for RtypeBitmap {
    type Err = RtypeBitmapError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let bytes = parser.parse_bytes(len)?;
        RtypeBitmap::from_bytes(bytes)
    }
}

impl Compose for RtypeBitmap {
    fn compose_len(&self) -> usize {
        self.0.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.0.compose(buf)
    }
}

impl Compress for RtypeBitmap {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}

//--- Scan and Display

impl Scan for RtypeBitmap {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>) -> Result<Self, ScanError> {
        let mut builder = RtypeBitmapBuilder::new();
        while let Ok(rtype) = Rtype::scan(scanner) {
            builder.add(rtype)
        }
        Ok(builder.finalize())
    }
}

impl fmt::Display for RtypeBitmap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let first = true;
        for rtype in self {
            if first {
                rtype.fmt(f)?
            } else {
                write!(f, " {}", rtype)?
            }
        }
        Ok(())
    }
}

//------------ RtypeBitmapBuilder --------------------------------------------

/// A builder for a record type bitmap.
//
//  Here is how this is going to work: We keep one long BytesMut into which
//  we place all added types. The buffer contains a sequence of blocks
//  encoded similar to the final format but with all 32 octets of the
//  bitmap present. Blocks are in order and are only added when needed (which
//  means we may have to insert a block in the middle). When finalizing, we
//  compress the block buffer by dropping the unncessary octets of each
//  block.
#[derive(Clone, Debug)]
pub struct RtypeBitmapBuilder {
    buf: BytesMut,
}

impl RtypeBitmapBuilder {
    pub fn new() -> Self {
        RtypeBitmapBuilder {
            // Start out with the capacity for one block.
            buf: BytesMut::with_capacity(34),
        }
    }

    pub fn add(&mut self, rtype: Rtype) {
        let (block, octet, bit) = split_rtype(rtype);
        let block = self.get_block(block);
        if (block[1] as usize) < (octet + 1) {
            block[1] = (octet + 1) as u8
        }
        block[octet + 2] |= bit;
    }

    fn get_block(&mut self, block: u8) -> &mut [u8] {
        let mut pos = 0;
        while pos < self.buf.len() {
            if self.buf[pos] == block {
                return &mut self.buf[pos..pos + 34];
            } else if self.buf[pos] > block {
                let len = self.buf.len() - pos;
                self.buf.extend_from_slice(&[0; 34]);
                unsafe {
                    ptr::copy(
                        self.buf.as_ptr().offset(pos as isize),
                        self.buf.as_mut_ptr().offset(pos as isize + 34),
                        len,
                    );
                    ptr::write_bytes(self.buf.as_mut_ptr().offset(pos as isize), 0, 34);
                }
                self.buf[pos] = block;
                return &mut self.buf[pos..pos + 34];
            } else {
                pos += 34
            }
        }

        self.buf.extend_from_slice(&[0; 34]);
        self.buf[pos] = block;
        &mut self.buf[pos..pos + 34]
    }

    pub fn finalize(mut self) -> RtypeBitmap {
        let mut src_pos = 0;
        let mut dst_pos = 0;
        while src_pos < self.buf.len() {
            let len = (self.buf[src_pos + 1] as usize) + 2;
            if src_pos != dst_pos {
                unsafe {
                    ptr::copy(
                        self.buf.as_ptr().offset(src_pos as isize),
                        self.buf.as_mut_ptr().offset(dst_pos as isize),
                        len,
                    )
                }
            }
            dst_pos += len;
            src_pos += 34;
        }
        self.buf.truncate(dst_pos);
        RtypeBitmap(self.buf.freeze())
    }
}

//--- Default

impl Default for RtypeBitmapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

//------------ RtypeBitmapIter -----------------------------------------------

pub struct RtypeBitmapIter<'a> {
    data: &'a [u8],
    block: u16,
    len: usize,

    octet: usize,
    bit: u16,
}

impl<'a> RtypeBitmapIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        if data.is_empty() {
            RtypeBitmapIter {
                data,
                block: 0,
                len: 0,
                octet: 0,
                bit: 0,
            }
        } else {
            let mut res = RtypeBitmapIter {
                data: &data[2..],
                block: u16::from(data[0]) << 8,
                len: usize::from(data[1]),
                octet: 0,
                bit: 0,
            };
            if res.data[0] & 0x80 == 0 {
                res.advance()
            }
            res
        }
    }

    fn advance(&mut self) {
        loop {
            self.bit += 1;
            if self.bit == 7 {
                self.bit = 0;
                self.octet += 1;
                if self.octet == self.len {
                    self.data = &self.data[self.len..];
                    if self.data.is_empty() {
                        return;
                    }
                    self.block = u16::from(self.data[0]) << 8;
                    self.len = self.data[1] as usize;
                    self.octet = 0;
                }
            }
            if self.data[self.octet] & (0x80 >> self.bit) != 0 {
                return;
            }
        }
    }
}

impl<'a> Iterator for RtypeBitmapIter<'a> {
    type Item = Rtype;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        let res =
            Rtype::from_int(u16::from(self.data[0]) << 8 | (self.octet as u16) << 3 | self.bit);
        self.advance();
        Some(res)
    }
}

//------------ ParseNsecError ------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum ParseNsecError<E: Fail> {
    #[fail(display = "short field")]
    ShortField,

    #[fail(display = "{}", _0)]
    BadNextName(E),

    #[fail(display = "invalid record type bitmap")]
    BadRtypeBitmap,
}

impl<E: Fail> From<ShortBuf> for ParseNsecError<E> {
    fn from(_: ShortBuf) -> Self {
        ParseNsecError::ShortField
    }
}

impl<E: Fail> From<RtypeBitmapError> for ParseNsecError<E> {
    fn from(err: RtypeBitmapError) -> Self {
        match err {
            RtypeBitmapError::ShortBuf => ParseNsecError::ShortField,
            RtypeBitmapError::BadRtypeBitmap => ParseNsecError::BadRtypeBitmap,
        }
    }
}

//------------ RtypeBitmapError ----------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum RtypeBitmapError {
    #[fail(display = "short field")]
    ShortBuf,

    #[fail(display = "invalid record type bitmap")]
    BadRtypeBitmap,
}

impl From<ShortBuf> for RtypeBitmapError {
    fn from(_: ShortBuf) -> Self {
        RtypeBitmapError::ShortBuf
    }
}

//------------ parsed --------------------------------------------------------

pub mod parsed {
    pub use super::{Dnskey, Ds, Nsec, Rrsig};
}

//------------ Friendly Helper Functions -------------------------------------

/// Splits an Rtype value into window number, octet number, and octet mask.
fn split_rtype(rtype: Rtype) -> (u8, usize, u8) {
    let rtype = rtype.to_int();
    (
        (rtype >> 8) as u8,
        ((rtype & 0xFF) >> 3) as usize,
        0x80u8 >> (rtype & 0x07),
    )
}

//============ Test ==========================================================

#[cfg(test)]
mod test {
    extern crate base64;
    use super::*;
    use iana::{Class, Rtype};

    // Returns current root KSK/ZSK for testing.
    fn root_pubkey() -> (Dnskey, Dnskey) {
        let ksk = base64::decode("AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=").unwrap().into();
        let zsk = base64::decode("AwEAAeVDC34GZILwsQJy97K2Fst4P3XYZrXLyrkausYzSqEjSUulgh+iLgHg0y7FIF890+sIjXsk7KLJUmCOWfYWPorNKEOKLk5Zx/4M6D3IHZE3O3m/Eahrc28qQzmTLxiMZAW65MvR2UO3LxVtYOPBEBiDgAQD47x2JLsJYtavCzNL5WiUk59OgvHmDqmcC7VXYBhK8V8Tic089XJgExGeplKWUt9yyc31ra1swJX51XsOaQz17+vyLVH8AZP26KvKFiZeoRbaq6vl+hc8HQnI2ug5rA2zoz3MsSQBvP1f/HvqsWxLqwXXKyDD1QM639U+XzVB8CYigyscRP22QCnwKIU=").unwrap().into();
        (
            Dnskey::new(257, 3, SecAlg::RsaSha256, ksk),
            Dnskey::new(256, 3, SecAlg::RsaSha256, zsk),
        )
    }

    #[test]
    fn rtype_bitmap_builder() {
        let mut builder = RtypeBitmapBuilder::new();
        builder.add(Rtype::Int(1234)); // 0x04D2
        builder.add(Rtype::A); // 0x0001
        builder.add(Rtype::Mx); // 0x000F
        builder.add(Rtype::Rrsig); // 0x002E
        builder.add(Rtype::Nsec); // 0x002F
        assert_eq!(
            builder.finalize().as_slice(),
            &b"\x00\x06\x40\x01\x00\x00\x00\x03\
                     \x04\x1b\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x20"[..]
        );
    }

    #[test]
    fn dnskey_flags() {
        let (ksk, zsk) = root_pubkey();
        assert_eq!(ksk.is_zsk(), true);
        assert_eq!(zsk.is_zsk(), true);
        assert_eq!(ksk.is_secure_entry_point(), true);
        assert_eq!(zsk.is_secure_entry_point(), false);
        assert_eq!(ksk.is_revoked(), false);
        assert_eq!(zsk.is_revoked(), false);
    }

    #[test]
    fn dnskey_digest() {
        let (dnskey, _) = root_pubkey();
        let owner = Dname::root();
        let expected = Ds::new(
            20326,
            SecAlg::RsaSha256,
            DigestAlg::Sha256,
            base64::decode("4G1EuAuPHTmpXAsNfGXQhFjogECbvGg0VxBCN8f47I0=")
                .unwrap()
                .into(),
        );
        assert_eq!(dnskey.key_tag(), expected.key_tag());
        assert_eq!(
            dnskey.digest(&owner, DigestAlg::Sha256).unwrap().as_ref(),
            expected.digest().as_ref()
        );
    }

    #[test]
    fn dnskey_digest_unsupported() {
        let (dnskey, _) = root_pubkey();
        let owner = Dname::root();
        assert_eq!(dnskey.digest(&owner, DigestAlg::Gost).is_err(), true);
    }

    fn rrsig_verify_dnskey(ksk: Dnskey, zsk: Dnskey, rrsig: Rrsig) {
        let mut records: Vec<_> = [&ksk, &zsk]
            .iter()
            .cloned()
            .map(|x| Record::new(rrsig.signer_name().clone(), Class::In, 0, x.clone()))
            .collect();
        let signed_data = {
            let mut buf = Vec::new();
            rrsig.signed_data(&mut buf, records.as_mut_slice());
            Bytes::from(buf)
        };

        // Test that the KSK is sorted after ZSK key
        assert_eq!(ksk.key_tag(), rrsig.key_tag());
        assert_eq!(ksk.key_tag(), records[1].data().key_tag());

        // Test verifier
        assert!(rrsig.verify_signed_data(&ksk, &signed_data).is_ok());
        assert!(rrsig.verify_signed_data(&zsk, &signed_data).is_err());
    }

    #[test]
    fn rrsig_verify_rsa_sha256() {
        let (ksk, zsk) = root_pubkey();
        let rrsig = Rrsig::new(Rtype::Dnskey, SecAlg::RsaSha256, 0, 172800, 1560211200.into(), 1558396800.into(), 20326, Dname::root(), base64::decode("otBkINZAQu7AvPKjr/xWIEE7+SoZtKgF8bzVynX6bfJMJuPay8jPvNmwXkZOdSoYlvFp0bk9JWJKCh8y5uoNfMFkN6OSrDkr3t0E+c8c0Mnmwkk5CETH3Gqxthi0yyRX5T4VlHU06/Ks4zI+XAgl3FBpOc554ivdzez8YCjAIGx7XgzzooEb7heMSlLc7S7/HNjw51TPRs4RxrAVcezieKCzPPpeWBhjE6R3oiSwrl0SBD4/yplrDlr7UHs/Atcm3MSgemdyr2sOoOUkVQCVpcj3SQQezoD2tCM7861CXEQdg5fjeHDtz285xHt5HJpA5cOcctRo4ihybfow/+V7AQ==").unwrap().into());
        rrsig_verify_dnskey(ksk, zsk, rrsig);
    }

    #[test]
    fn rrsig_verify_ecdsap256_sha256() {
        let (ksk, zsk) = (
            Dnskey::new(257, 3, SecAlg::EcdsaP256Sha256, base64::decode("mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==").unwrap().into()),
            Dnskey::new(256, 3, SecAlg::EcdsaP256Sha256, base64::decode("oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==").unwrap().into()),
        );

        let owner = Dname::from_slice(b"\x0acloudflare\x03com\x00").unwrap();
        let rrsig = Rrsig::new(Rtype::Dnskey, SecAlg::EcdsaP256Sha256, 2, 3600, 1560314494.into(), 1555130494.into(), 2371, owner.clone(), base64::decode("8jnAGhG7O52wmL065je10XQztRX1vK8P8KBSyo71Z6h5wAT9+GFxKBaEzcJBLvRmofYFDAhju21p1uTfLaYHrg==").unwrap().into());
        rrsig_verify_dnskey(ksk, zsk, rrsig);
    }

    #[test]
    fn rrsig_verify_ed25519() {
        let (ksk, zsk) = (
            Dnskey::new(
                257,
                3,
                SecAlg::Ed25519,
                base64::decode("m1NELLVVQKl4fHVn/KKdeNO0PrYKGT3IGbYseT8XcKo=")
                    .unwrap()
                    .into(),
            ),
            Dnskey::new(
                256,
                3,
                SecAlg::Ed25519,
                base64::decode("2tstZAjgmlDTePn0NVXrAHBJmg84LoaFVxzLl1anjGI=")
                    .unwrap()
                    .into(),
            ),
        );

        let owner = Dname::from_slice(b"\x07ed25519\x02nl\x00").unwrap();
        let rrsig = Rrsig::new(Rtype::Dnskey, SecAlg::Ed25519, 2, 3600, 1559174400.into(), 1557360000.into(), 45515, owner.clone(), base64::decode("hvPSS3E9Mx7lMARqtv6IGiw0NE0uz0mZewndJCHTkhwSYqlasUq7KfO5QdtgPXja7YkTaqzrYUbYk01J8ICsAA==").unwrap().into());
        rrsig_verify_dnskey(ksk, zsk, rrsig);
    }
}
