#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)] // I'm too lazy
#![cfg_attr(
    not(all(feature = "client", feature = "server")),
    allow(dead_code, unused_imports)
)]

mod config;
mod err;
pub mod hpke;
#[cfg(feature = "nss")]
mod nss;
#[cfg(feature = "rust-hpke")]
mod rand;
#[cfg(feature = "rust-hpke")]
mod rh;

use async_stream::stream;
use futures::{stream::Stream, StreamExt};
use futures_util::stream::once;

pub use crate::{
    config::{KeyConfig, SymmetricSuite},
    err::Error,
};

use crate::{
    err::Res,
    hpke::{Aead as AeadId, Kdf, Kem},
};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use log::{info, trace};
use std::{
    cmp::max,
    convert::TryFrom,
    io::{BufReader, Read},
    mem::size_of,
};

#[cfg(feature = "nss")]
use crate::nss::random;
#[cfg(feature = "nss")]
use crate::nss::{
    aead::{Aead, Mode, NONCE_LEN},
    hkdf::{Hkdf, KeyMechanism},
    hpke::{Config as HpkeConfig, Exporter, HpkeR, HpkeS},
};

#[cfg(feature = "rust-hpke")]
use crate::rand::random;
#[cfg(feature = "rust-hpke")]
use crate::rh::{
    aead::{Aead, Mode, NONCE_LEN},
    hkdf::{Hkdf, KeyMechanism},
    hpke::{Config as HpkeConfig, Exporter, HpkeR, HpkeS},
};

/// The request header is a `KeyId` and 2 each for KEM, KDF, and AEAD identifiers
const REQUEST_HEADER_LEN: usize = size_of::<KeyId>() + 6;
const INFO_REQUEST: &[u8] = b"message/bhttp request";
/// The info used for HPKE export is `INFO_REQUEST`, a zero byte, and the header.
const INFO_LEN: usize = INFO_REQUEST.len() + 1 + REQUEST_HEADER_LEN;
const LABEL_RESPONSE: &[u8] = b"message/bhttp response";
const INFO_KEY: &[u8] = b"key";
const INFO_NONCE: &[u8] = b"nonce";

/// The type of a key identifier.
pub type KeyId = u8;

pub fn init() {
    #[cfg(feature = "nss")]
    nss::init();
}

/// Construct the info parameter we use to initialize an `HpkeS` instance.
fn build_info(key_id: KeyId, config: HpkeConfig) -> Res<Vec<u8>> {
    let mut info = Vec::with_capacity(INFO_LEN);
    info.extend_from_slice(INFO_REQUEST);
    info.push(0);
    info.write_u8(key_id)?;
    info.write_u16::<NetworkEndian>(u16::from(config.kem()))?;
    info.write_u16::<NetworkEndian>(u16::from(config.kdf()))?;
    info.write_u16::<NetworkEndian>(u16::from(config.aead()))?;
    trace!("HPKE info: {}", hex::encode(&info));
    Ok(info)
}

/// This is the sort of information we expect to receive from the receiver.
/// This might not be necessary if we agree on a format.
#[cfg(feature = "client")]
pub struct ClientRequest {
    hpke: HpkeS,
    header: Vec<u8>,
}

#[cfg(feature = "client")]
impl ClientRequest {
    /// Construct a `ClientRequest` from a specific `KeyConfig` instance.
    pub fn from_config(config: &mut KeyConfig) -> Res<Self> {
        // TODO(mt) choose the best config, not just the first.
        let selected = config.select(config.symmetric[0])?;

        // Build the info, which contains the message header.
        let info = build_info(config.key_id, selected)?;
        let hpke = HpkeS::new(selected, &mut config.pk, &info)?;

        let header = Vec::from(&info[INFO_REQUEST.len() + 1..]);
        debug_assert_eq!(header.len(), REQUEST_HEADER_LEN);
        Ok(Self { hpke, header })
    }

    /// Reads an encoded configuration and constructs a single use client sender.
    /// See `KeyConfig::decode` for the structure details.
    pub fn from_encoded_config(encoded_config: &[u8]) -> Res<Self> {
        let mut config = KeyConfig::decode(encoded_config)?;
        Self::from_config(&mut config)
    }

    /// Reads an encoded list of configurations and constructs a single use client sender
    /// from the first supported configuration.
    /// See `KeyConfig::decode_list` for the structure details.
    pub fn from_encoded_config_list(encoded_config_list: &[u8]) -> Res<Self> {
        let mut configs = KeyConfig::decode_list(encoded_config_list)?;
        if let Some(mut config) = configs.pop() {
            Self::from_config(&mut config)
        } else {
            Err(Error::Unsupported)
        }
    }

    /// Encapsulate a request.  This consumes this object.
    /// This produces a response handler and the bytes of an encapsulated request.
    pub fn encapsulate(mut self, request: &[u8]) -> Res<(Vec<u8>, ClientResponse)> {
        let extra =
            self.hpke.config().kem().n_enc() + self.hpke.config().aead().n_t() + request.len();
        let expected_len = self.header.len() + extra;

        let mut enc_request = self.header;
        enc_request.reserve_exact(extra);

        let enc = self.hpke.enc()?;
        enc_request.extend_from_slice(&enc);

        let mut ct = self.hpke.seal(&[], request)?;
        enc_request.append(&mut ct);

        debug_assert_eq!(expected_len, enc_request.len());
        Ok((enc_request, ClientResponse::new(self.hpke, enc)))
    }
}

/// A server can handle multiple requests.
/// It holds a single key pair and can generate a configuration.
/// (A more complex server would have multiple key pairs. This is simple.)
#[cfg(feature = "server")]
#[derive(Debug, Clone)]
pub struct Server {
    config: KeyConfig,
}

#[cfg(feature = "server")]
impl Server {
    /// Create a new server configuration.
    /// # Panics
    /// If the configuration doesn't include a private key.
    pub fn new(config: KeyConfig) -> Res<Self> {
        assert!(config.sk.is_some());
        Ok(Self { config })
    }

    /// Get the configuration that this server uses.
    #[must_use]
    pub fn config(&self) -> &KeyConfig {
        &self.config
    }

    /// Remove encapsulation on a message.
    /// # Panics
    /// Not as a consequence of this code, but Rust won't know that for sure.
    #[allow(clippy::similar_names)] // for kem_id and key_id
    pub fn decapsulate(&self, enc_request: &[u8]) -> Res<(Vec<u8>, ServerResponse)> {
        if enc_request.len() < REQUEST_HEADER_LEN {
            return Err(Error::Truncated);
        }
        let mut r = BufReader::new(enc_request);
        let key_id = r.read_u8()?;
        if key_id != self.config.key_id {
            return Err(Error::KeyId);
        }
        let kem_id = Kem::try_from(r.read_u16::<NetworkEndian>()?)?;
        if kem_id != self.config.kem {
            return Err(Error::InvalidKem);
        }
        let kdf_id = Kdf::try_from(r.read_u16::<NetworkEndian>()?)?;
        let aead_id = AeadId::try_from(r.read_u16::<NetworkEndian>()?)?;
        let sym = SymmetricSuite::new(kdf_id, aead_id);

        let info = build_info(
            key_id,
            HpkeConfig::new(self.config.kem, sym.kdf(), sym.aead()),
        )?;

        let cfg = self.config.select(sym)?;
        let mut enc = vec![0; cfg.kem().n_enc()];
        r.read_exact(&mut enc)?;
        let mut hpke = HpkeR::new(
            cfg,
            &self.config.pk,
            self.config.sk.as_ref().unwrap(),
            &enc,
            &info,
        )?;

        let mut ct = Vec::new();
        r.read_to_end(&mut ct)?;

        let request = hpke.open(&[], &ct)?;
        Ok((request, ServerResponse::new(&hpke, enc)?))
    }
}

fn entropy(config: HpkeConfig) -> usize {
    max(config.aead().n_n(), config.aead().n_k())
}

fn make_aead(
    mode: Mode,
    cfg: HpkeConfig,
    exp: &impl Exporter,
    enc: Vec<u8>,
    response_nonce: &[u8],
) -> Res<Aead> {
    let secret = exp.export(LABEL_RESPONSE, entropy(cfg))?;
    let mut salt = enc;
    salt.extend_from_slice(response_nonce);

    let hkdf = Hkdf::new(cfg.kdf());
    let prk = hkdf.extract(&salt, &secret)?;

    let key = hkdf.expand_key(&prk, INFO_KEY, KeyMechanism::Aead(cfg.aead()))?;
    let iv = hkdf.expand_data(&prk, INFO_NONCE, cfg.aead().n_n())?;
    let nonce_base = <[u8; NONCE_LEN]>::try_from(iv).unwrap();

    Aead::new(mode, cfg.aead(), &key, nonce_base)
}

/// An object for encapsulating responses.
/// The only way to obtain one of these is through `Server::decapsulate()`.
#[cfg(feature = "server")]
pub struct ServerResponse {
    response_nonce: Vec<u8>,
    aead: Aead,
}

#[cfg(feature = "server")]
impl ServerResponse {
    fn new(hpke: &HpkeR, enc: Vec<u8>) -> Res<Self> {
        let response_nonce = random(entropy(hpke.config()));
        let aead = make_aead(Mode::Encrypt, hpke.config(), hpke, enc, &response_nonce)?;
        Ok(Self {
            response_nonce,
            aead,
        })
    }

    // Variable length encoding of an integer
    fn variant_encode(&mut self, mut val: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (val & 0x7F) as u8; // Take the last 7 bits
            val >>= 7; // Shift right by 7 bits
            if val != 0 {
                byte |= 0x80; // Set the MSB if there's more to encode
            }
            bytes.push(byte);
            if val == 0 {
                break;
            }
        }
        bytes
    }

    /// Consume this object by encapsulating a response.
    pub fn encapsulate(mut self, response: &[u8]) -> Res<Vec<u8>> {
        let mut enc_response = self.response_nonce;
        let mut ct = self.aead.seal(&[], response)?;
        enc_response.append(&mut ct);
        Ok(enc_response)
    }

    // Consume this object by encapsulating a stream
    // https://www.ietf.org/archive/id/draft-ohai-chunked-ohttp-01.html#name-response-format
    // Chunked Encapsulated Response {
    //   Response Nonce (Nk),
    //   Chunked Response Chunks (..),
    // }

    // Chunked Response Chunks {
    //   Non-Final Response Chunk (..),
    //   Final Response Chunk Indicator (i) = 0,
    //   AEAD-Protected Final Response Chunk (..),
    // }

    // Non-Final Response Chunk {
    //   Length (i) = 1..,
    //   AEAD-Protected Chunk (..),
    // }
    pub fn encapsulate_stream<S, E>(
        mut self,
        input: S,
    ) -> std::pin::Pin<Box<dyn Stream<Item = Res<Vec<u8>>> + Send + 'static>>
    where
        S: Stream<Item = Result<Vec<u8>, E>> + Send + 'static,
        E: std::fmt::Debug + Send,
    {
        // Response Nonce (Nk)
        let response_nonce = Ok(self.response_nonce.clone());
        info!("Response nonce {}", hex::encode(&self.response_nonce.clone()));
        let nonce_stream = once(async { response_nonce });

        let mut input = Box::pin(input);
        let output_stream = stream! {
            let current = input.next().await;
            let Some(current) = current else { return };
            let Ok(mut current) = current else { return };
            
            loop {
                //info!("Processing chunk {}", std::str::from_utf8(&current).unwrap());
                if let Some(next) = input.next().await {
                    let mut enc_response = Vec::new();

                    // Non-Final Response Chunk (..),
                    let aad = "";
                    let mut ct = self.aead.seal(aad.as_bytes(), &current).unwrap();
                    let mut enc_length = self.variant_encode(ct.len());
                    // Length (i) = 1..,
                    enc_response.append(&mut enc_length);

                    // AEAD-Protected Chunk (..),
                    enc_response.append(&mut ct);

                    info!("Encapsulated chunk {}({})", hex::encode(&enc_response), enc_response.len());
                    yield Ok(enc_response);
                    current = next.unwrap();
                } else {
                    let mut enc_response = Vec::new();

                    // Final Response Chunk Indicator (i) = 0,
                    let mut final_chunk_indicator = self.variant_encode(0);
                    enc_response.append(&mut final_chunk_indicator);

                    // AEAD-Protected Final Response Chunk (..),
                    let aad = "final";
                    let mut ct = self.aead.seal(aad.as_bytes(), &current).unwrap();
                    let mut enc_length = self.variant_encode(ct.len());
                    enc_response.append(&mut enc_length);
                    enc_response.append(&mut ct);
                    info!("Encapsulated final chunk {}({})", hex::encode(&enc_response), enc_response.len());
                    yield Ok(enc_response);
                    return;
                }
            }
        };

        let stream = nonce_stream.chain(output_stream);
        Box::pin(stream)
    }
}

#[cfg(feature = "server")]
impl std::fmt::Debug for ServerResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerResponse")
    }
}

/// An object for decapsulating responses.
/// The only way to obtain one of these is through `ClientRequest::encapsulate()`.
#[cfg(feature = "client")]
pub struct ClientResponse {
    hpke: HpkeS,
    enc: Vec<u8>,
    seq: u64,
    aead: Option<Aead>,
}

#[cfg(feature = "client")]
impl ClientResponse {
    /// Private method for constructing one of these.
    /// Doesn't do anything because we don't have the nonce yet, so
    /// the work that can be done is limited.
    fn new(hpke: HpkeS, enc: Vec<u8>) -> Self {
        let seq = 0;
        let aead = None;
        Self {
            hpke,
            enc,
            seq,
            aead,
        }
    }

    /// Consume this object by decapsulating a response.
    pub fn decapsulate(self, enc_response: &[u8]) -> Res<Vec<u8>> {
        let mid = entropy(self.hpke.config());
        if mid >= enc_response.len() {
            return Err(Error::Truncated);
        }
        let (response_nonce, ct) = enc_response.split_at(mid);
        let mut aead = make_aead(
            Mode::Decrypt,
            self.hpke.config(),
            &self.hpke,
            self.enc,
            response_nonce,
        )?;
        aead.open(&[], 0, ct) // 0 is the sequence number
    }

    fn set_response_nonce(&mut self, enc_response: &[u8]) -> Res<()> {
        let mid = entropy(self.hpke.config());
        if mid != enc_response.len() {
            return Err(Error::Truncated);
        }
        let aead = make_aead(
            Mode::Decrypt,
            self.hpke.config(),
            &self.hpke,
            self.enc.clone(),
            enc_response,
        )?;
        self.aead = Some(aead);
        Ok(())
    }

    fn variant_decode(&mut self, bytes: &[u8]) -> Result<(u64, usize), String> {
        let mut value: u64 = 0;
        let mut shift = 0;
        let mut bytes_read = 0;

        for &byte in bytes {
            let byte_value = (byte & 0x7F) as u64;
            value |= byte_value << shift;
            bytes_read += 1;
            if byte & 0x80 == 0 {
                // Continuation bit is not set, end of the VLQ-encoded integer
                return Ok((value, bytes_read));
            }
            shift += 7;
            if shift >= 64 {
                return Err("VLQ-encoded integer is too large".to_string());
            }
        }
        Err("Incomplete VLQ-encoded integer".to_string())
    }

    pub async fn decapsulate_stream<S>(
        mut self,
        mut stream: S,
    ) -> std::pin::Pin<Box<dyn Stream<Item = Res<Vec<u8>>> + Send + 'static>>
    where
        S: Stream<Item = Res<Vec<u8>>> + Send + 'static + Unpin,
    {
        let mut nonce_received = false;
        let mut aad = "";
        let nonce_size = entropy(self.hpke.config());
        let mut buffer: Vec<u8> = Vec::new();
        let output_stream = stream! {
            while let Some(next) = stream.next().await {
                let mut enc_response = next.unwrap();
                info!("Received chunk: {}({})", hex::encode(&enc_response), enc_response.len());
                buffer.append(&mut enc_response);
                info!("Buffer size {}", buffer.len());

                // Response Nonce (Nk)
                if !nonce_received && buffer.len() >= nonce_size {
                    nonce_received = true;
                    let nonce: Vec<_> = buffer.drain(0..nonce_size).collect();
                    info!("Setting response nonce: {}({})", hex::encode(&nonce), nonce.len());
                    self.set_response_nonce(&nonce).unwrap();
                }

                while nonce_received && !buffer.is_empty() {
                    let (mut len, bytes_read) = self.variant_decode(&buffer).unwrap();
                    info!("Buffer state: {}, {}({})", buffer.len(), len, bytes_read);

                    // Final Response Chunk Indicator (i) = 0,
                    if len == 0 {
                        buffer.drain(0..bytes_read);
                        info!("Processing final chunk");
                        aad = "final";
                        let (length, bytes_read) = self.variant_decode(&buffer).unwrap();
                        info!("Buffer state: {}({})", length, bytes_read);
                        len = length;
                    }

                    // Decapsulate chunk if received
                    if buffer.len() >= (len as usize){
                        buffer.drain(0..bytes_read);
                        let ct: Vec<_> = buffer.drain(0..(len as usize)).collect();
                        info!("Decapsulating chunk {}({})", hex::encode(&ct), len);
                        self.seq += 1;
                        yield self.aead.as_mut().unwrap().open(aad.as_bytes(), self.seq - 1, &ct);
                    } else {
                        break;
                    }    
                }
            }
        };

        Box::pin(output_stream)
    }
}

#[cfg(all(test, feature = "client", feature = "server"))]
mod test {
    use crate::{
        config::SymmetricSuite,
        err::Res,
        hpke::{Aead, Kdf, Kem},
        ClientRequest, Error, KeyConfig, KeyId, Server,
    };

    use futures::StreamExt;
    use log::trace;
    use std::{fmt::Debug, io::ErrorKind};

    use async_stream::stream;
    
    const KEY_ID: KeyId = 1;
    const KEM: Kem = Kem::X25519Sha256;
    const SYMMETRIC: &[SymmetricSuite] = &[
        SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
        SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
    ];

    const REQUEST: &[u8] = &[
        0x00, 0x03, 0x47, 0x45, 0x54, 0x05, 0x68, 0x74, 0x74, 0x70, 0x73, 0x0b, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x01, 0x2f,
    ];
    const RESPONSE: &[u8] = &[0x01, 0x40, 0xc8];

    fn init() {
        crate::init();
        _ = env_logger::try_init(); // ignore errors here
    }

    #[test]
    fn request_response() {
        init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();
        trace!("Config: {}", hex::encode(&encoded_config));

        let client = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (enc_request, client_response) = client.encapsulate(REQUEST).unwrap();
        trace!("Request: {}", hex::encode(REQUEST));
        trace!("Encapsulated Request: {}", hex::encode(&enc_request));

        let (request, server_response) = server.decapsulate(&enc_request).unwrap();
        assert_eq!(&request[..], REQUEST);

        let enc_response = server_response.encapsulate(RESPONSE).unwrap();
        trace!("Encapsulated Response: {}", hex::encode(&enc_response));

        let response = client_response.decapsulate(&enc_response).unwrap();
        assert_eq!(&response[..], RESPONSE);
        trace!("Response: {}", hex::encode(RESPONSE));
    }

    #[test]
    fn two_requests() {
        init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();

        let client1 = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (enc_request1, client_response1) = client1.encapsulate(REQUEST).unwrap();
        let client2 = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (enc_request2, client_response2) = client2.encapsulate(REQUEST).unwrap();
        assert_ne!(enc_request1, enc_request2);

        let (request1, server_response1) = server.decapsulate(&enc_request1).unwrap();
        assert_eq!(&request1[..], REQUEST);
        let (request2, server_response2) = server.decapsulate(&enc_request2).unwrap();
        assert_eq!(&request2[..], REQUEST);

        let enc_response1 = server_response1.encapsulate(RESPONSE).unwrap();
        let enc_response2 = server_response2.encapsulate(RESPONSE).unwrap();
        assert_ne!(enc_response1, enc_response2);

        let response1 = client_response1.decapsulate(&enc_response1).unwrap();
        assert_eq!(&response1[..], RESPONSE);
        let response2 = client_response2.decapsulate(&enc_response2).unwrap();
        assert_eq!(&response2[..], RESPONSE);
    }

    fn assert_truncated<T: Debug>(res: Res<T>) {
        match res.unwrap_err() {
            Error::Truncated => {}
            #[cfg(feature = "rust-hpke")]
            Error::Aead(_) => {}
            #[cfg(feature = "nss")]
            Error::Crypto(_) => {}
            Error::Io(e) => assert_eq!(e.kind(), ErrorKind::UnexpectedEof),
            e => panic!("unexpected error type: {e:?}"),
        }
    }

    fn request_truncated(cut: usize) {
        init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();

        let client = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (enc_request, _) = client.encapsulate(REQUEST).unwrap();

        let res = server.decapsulate(&enc_request[..cut]);
        assert_truncated(res);
    }

    #[test]
    fn request_truncated_header() {
        request_truncated(4);
    }

    #[test]
    fn request_truncated_enc() {
        // header is 7, enc is 32
        request_truncated(24);
    }

    #[test]
    fn request_truncated_ct() {
        // header and enc is 39, aead needs at least 16 more
        request_truncated(42);
    }

    fn response_truncated(cut: usize) {
        init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();

        let client = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (enc_request, client_response) = client.encapsulate(REQUEST).unwrap();

        let (request, server_response) = server.decapsulate(&enc_request).unwrap();
        assert_eq!(&request[..], REQUEST);

        let enc_response = server_response.encapsulate(RESPONSE).unwrap();

        let res = client_response.decapsulate(&enc_response[..cut]);
        assert_truncated(res);
    }

    #[test]
    fn response_truncated_ct() {
        // nonce is 16, aead needs at least 16 more
        response_truncated(20);
    }

    #[test]
    fn response_truncated_nonce() {
        response_truncated(7);
    }

    #[cfg(feature = "rust-hpke")]
    #[test]
    fn derive_key_pair() {
        const IKM: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ];
        const EXPECTED_CONFIG: &[u8] = &[
            0x01, 0x00, 0x20, 0xfc, 0x01, 0x38, 0x93, 0x64, 0x10, 0x31, 0x1a, 0x0c, 0x64, 0x1a,
            0x5c, 0xa0, 0x86, 0x39, 0x1d, 0xe8, 0xe7, 0x03, 0x82, 0x33, 0x3f, 0x6d, 0x64, 0x49,
            0x25, 0x21, 0xad, 0x7d, 0xc7, 0x8a, 0x5d, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x03,
        ];

        init();

        let config = KeyConfig::decode(EXPECTED_CONFIG).unwrap();

        let new_config = KeyConfig::derive(KEY_ID, KEM, Vec::from(SYMMETRIC), IKM).unwrap();
        assert_eq!(config.key_id, new_config.key_id);
        assert_eq!(config.kem, new_config.kem);
        assert_eq!(config.symmetric, new_config.symmetric);

        let server = Server::new(new_config).unwrap();
        let encoded_config = server.config().encode().unwrap();
        assert_eq!(EXPECTED_CONFIG, encoded_config);
    }

    #[test]
    fn request_from_config_list() {
        init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();

        let mut header: [u8; 2] = [0; 2];
        header[0] = u8::try_from((encoded_config.len() & 0xFF00) >> 8).unwrap();
        header[1] = u8::try_from(encoded_config.len() & 0xFF).unwrap();
        let mut encoded_config_list = Vec::new();
        encoded_config_list.extend(header.to_vec());
        encoded_config_list.extend(encoded_config);

        let client = ClientRequest::from_encoded_config_list(&encoded_config_list).unwrap();
        let (enc_request, client_response) = client.encapsulate(REQUEST).unwrap();

        let (request, server_response) = server.decapsulate(&enc_request).unwrap();
        assert_eq!(&request[..], REQUEST);

        let enc_response = server_response.encapsulate(RESPONSE).unwrap();

        let response = client_response.decapsulate(&enc_response).unwrap();
        assert_eq!(&response[..], RESPONSE);
    }

    #[tokio::test]
    async fn response_stream() {
        init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();
        trace!("Config: {}", hex::encode(&encoded_config));

        let client = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (enc_request, client_response) = client.encapsulate(REQUEST).unwrap();
        trace!("Request: {}", hex::encode(REQUEST));
        trace!("Encapsulated Request: {}", hex::encode(&enc_request));

        let (request, server_response) = server.decapsulate(&enc_request).unwrap();
        assert_eq!(&request[..], REQUEST);

        let stream = stream! { yield Ok::<Vec<u8>, Error>(RESPONSE.to_vec()); };
        let enc_response = server_response.encapsulate_stream(stream);

        let mut response = client_response.decapsulate_stream(enc_response).await;
        let next = response.next().await;
        assert!(next.is_some_and(|x| x.is_ok_and(|x| x.eq_ignore_ascii_case(RESPONSE))));
    }

    #[tokio::test]
    async fn two_response_stream() {
        init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();
        trace!("Config: {}", hex::encode(&encoded_config));

        let client = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (enc_request, client_response) = client.encapsulate(REQUEST).unwrap();
        trace!("Request: {}", hex::encode(REQUEST));
        trace!("Encapsulated Request: {}", hex::encode(&enc_request));

        let (request, server_response) = server.decapsulate(&enc_request).unwrap();
        assert_eq!(&request[..], REQUEST);

        let stream = stream! { 
            yield Ok::<Vec<u8>, Error>(RESPONSE.to_vec()); 
            yield Ok::<Vec<u8>, Error>(RESPONSE.to_vec()); 
        };
        let enc_response = server_response.encapsulate_stream(stream);

        let mut response = client_response.decapsulate_stream(enc_response).await;
        let next = response.next().await;
        assert!(next.is_some_and(|x| x.is_ok_and(|x| x.eq_ignore_ascii_case(RESPONSE))));

        let next = response.next().await;
        assert!(next.is_some_and(|x| x.is_ok_and(|x| x.eq_ignore_ascii_case(RESPONSE))));        
    }

    #[tokio::test]
    async fn two_response_stream_merged() {
        init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();
        trace!("Config: {}", hex::encode(&encoded_config));

        let client = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (enc_request, client_response) = client.encapsulate(REQUEST).unwrap();
        trace!("Request: {}", hex::encode(REQUEST));
        trace!("Encapsulated Request: {}", hex::encode(&enc_request));

        let (request, server_response) = server.decapsulate(&enc_request).unwrap();
        assert_eq!(&request[..], REQUEST);

        let stream = stream! { 
            yield Ok::<Vec<u8>, Error>(RESPONSE.to_vec()); 
            yield Ok::<Vec<u8>, Error>(RESPONSE.to_vec()); 
        };
        let enc_response = server_response.encapsulate_stream(stream);

        let merged_response = enc_response.chunks(2).map(|chunk| {
            if chunk.len() == 2 {
                println!("Found too elements");
                let mut first = chunk[0].as_ref().unwrap().clone();
                let second = chunk[1].as_ref().unwrap();
                first.append(&mut second.clone());
                Ok::<Vec<u8>, Error>(first.clone())
            } else {
                Ok::<Vec<u8>, Error>(chunk[0].as_ref().unwrap().clone())
            }
        });

        let mut response = client_response.decapsulate_stream(merged_response).await;

        let mut count = 0;
        while let Some(next) = response.next().await {
            count = count + 1;
            assert!(next.is_ok_and(|x| x.eq_ignore_ascii_case(RESPONSE)));
        }
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn three_response_stream_merged() {
        init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();
        trace!("Config: {}", hex::encode(&encoded_config));

        let client = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (enc_request, client_response) = client.encapsulate(REQUEST).unwrap();
        trace!("Request: {}", hex::encode(REQUEST));
        trace!("Encapsulated Request: {}", hex::encode(&enc_request));

        let (request, server_response) = server.decapsulate(&enc_request).unwrap();
        assert_eq!(&request[..], REQUEST);

        let stream = stream! { 
            yield Ok::<Vec<u8>, Error>(RESPONSE.to_vec()); 
            yield Ok::<Vec<u8>, Error>(RESPONSE.to_vec()); 
            yield Ok::<Vec<u8>, Error>(RESPONSE.to_vec()); 
        };
        let enc_response = server_response.encapsulate_stream(stream);

        let merged_response = enc_response.chunks(2).map(|chunk| {
            if chunk.len() == 2 {
                let mut first = chunk[0].as_ref().unwrap().clone();
                let second = chunk[1].as_ref().unwrap();
                first.append(&mut second.clone());
                Ok::<Vec<u8>, Error>(first.clone())
            } else {
                Ok::<Vec<u8>, Error>(chunk[0].as_ref().unwrap().clone())
            }
        });

        let mut response = client_response.decapsulate_stream(merged_response).await;
        let mut count = 0;
        while let Some(next) = response.next().await {
            count = count + 1;
            assert!(next.is_ok_and(|x| x.eq_ignore_ascii_case(RESPONSE)));
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn response_stream_fragment() {
        init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();
        trace!("Config: {}", hex::encode(&encoded_config));

        let client = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (enc_request, client_response) = client.encapsulate(REQUEST).unwrap();
        trace!("Request: {}", hex::encode(REQUEST));
        trace!("Encapsulated Request: {}", hex::encode(&enc_request));

        let (request, server_response) = server.decapsulate(&enc_request).unwrap();
        assert_eq!(&request[..], REQUEST);

        let stream = stream! { yield Ok::<Vec<u8>, Error>(RESPONSE.to_vec()); };
        let enc_response = server_response.encapsulate_stream(stream);

        let fragmented_response = enc_response.flat_map(|chunk| {
            let c = chunk.unwrap();
            if c.len() % 4 == 0 {
                let chunks: Vec<_> = c
                .chunks(4)
                .map(|c| Ok::<Vec<u8>, Error>(c.to_vec())).collect();
                futures_util::stream::iter(chunks)
            } else if c.len() % 3 == 0 {
                let chunks: Vec<_> = c
                .chunks(3)
                .map(|c| Ok::<Vec<u8>, Error>(c.to_vec())).collect();
                futures_util::stream::iter(chunks)
            } else {
                let vec = vec![Ok::<Vec<u8>, Error>(c)];
                futures_util::stream::iter(vec)
            }
        });

        let mut response = client_response.decapsulate_stream(fragmented_response).await;
        let next = response.next().await;
        assert!(next.is_some_and(|x| x.is_ok_and(|x| x.eq_ignore_ascii_case(RESPONSE))));
    }
}
