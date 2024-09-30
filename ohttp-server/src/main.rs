#![deny(clippy::pedantic)]

use std::{io::Cursor, net::SocketAddr, sync::Arc};

use futures_util::stream::unfold;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method, Response, Url,
};
use tokio::sync::Mutex;

use bhttp::{Message, Mode};
use ohttp::{
    hpke::{Aead, Kdf, Kem},
    KeyConfig, Server as OhttpServer, ServerResponse, SymmetricSuite,
};
use clap::Parser;
use warp::hyper::Body;
use warp::Filter;

use tokio::time::sleep;
use tokio::time::Duration;

use cgpuvm_attest::attest;
use reqwest::Client;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

use serde_cbor::Value;
use serde_json::from_str;

use hpke::Deserializable;
use serde::Deserialize;

use log::{info, trace, error};

#[derive(Deserialize)]
struct ExportedKey {
    kid: u8,
    key: String,
    receipt: String,
}

const DEFAULT_KMS_URL: &str = "https://acceu-aml-504.confidential-ledger.azure.com/key";
const DEFAULT_MAA_URL: &str = "https://sharedeus2.eus2.attest.azure.net";

#[derive(Debug, Parser)]
#[command(name = "ohttp-server", about = "Serve oblivious HTTP requests.")]
struct Args {
    /// The address to bind to.
    #[arg(default_value = "127.0.0.1:9443")]
    address: SocketAddr,

    /// When creating message/bhttp, use the indeterminate-length form.
    #[arg(long, short = 'n', alias = "indefinite")]
    indeterminate: bool,

    /// Target server
    #[arg(long, short = 't', default_value = "http://127.0.0.1:8000")]
    target: Url,

    /// Obtain key configuration from a KMS after attestation
    #[arg(long, short = 'a')]
    attest: bool,

    /// MAA endpoint
    #[arg(long, short = 'm')]
    maa_url: Option<String>,

    /// KMS endpoint
    #[arg(long, short = 's')]
    kms_url: Option<String>,

    /// Enable tracing
    #[structopt(long)]
    trace: bool,
}

impl Args {
    fn mode(&self) -> Mode {
        if self.indeterminate {
            Mode::IndeterminateLength
        } else {
            Mode::KnownLength
        }
    }
}

async fn generate_reply(
    ohttp_ref: &Arc<Mutex<OhttpServer>>,
    enc_request: &[u8],
    target: Url,
    _mode: Mode,
) -> Res<(Response, ServerResponse)> {
    let ohttp = ohttp_ref.lock().await;
    info!("Recevied encapsulated score request for target {}", target);
    let (request, server_response) = ohttp.decapsulate(enc_request)?;
    let bin_request = Message::read_bhttp(&mut Cursor::new(&request[..]))?;

    let method: Method = if let Some(method_bytes) = bin_request.control().method() {
        Method::from_bytes(method_bytes)?
    } else {
        Method::GET
    };

    let mut headers = HeaderMap::new();
    for field in bin_request.header().fields() {
        headers.append(
            HeaderName::from_bytes(field.name()).unwrap(),
            HeaderValue::from_bytes(field.value()).unwrap(),
        );
    }

    let mut t = target;
    if let Some(path_bytes) = bin_request.control().path() {
        if let Ok(path_str) = std::str::from_utf8(path_bytes) {
            t.set_path(path_str);
        }
    }

    let client = reqwest::ClientBuilder::new().build()?;
    let response = client
        .request(method, t)
        .headers(headers)
        .body(bin_request.content().to_vec())
        .send()
        .await?
        .error_for_status()?;

    Ok((response, server_response))
}

#[allow(clippy::unused_async)]
async fn score(
    body: warp::hyper::body::Bytes,
    ohttp: Arc<Mutex<OhttpServer>>,
    target: Url,
    mode: Mode,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    match generate_reply(&ohttp, &body[..], target, mode).await {
        Ok((response, server_response)) => {
            let stream = Box::pin(unfold(response, |mut response| async move {
                match response.chunk().await {
                    Ok(Some(chunk)) => Some((Ok::<Vec<u8>, ohttp::Error>(chunk.to_vec()), response)),
                    _ => None,
                }
            }));
        
            let stream = server_response.encapsulate_stream(stream);
            Ok(warp::http::Response::builder()
                .header("Content-Type", "message/ohttp-chunked-res")
                .body(Body::wrap_stream(stream)))
        }
        Err(e) => {
            error!("400 {}", e.to_string());
            if let Ok(oe) = e.downcast::<::ohttp::Error>() {
                Ok(warp::http::Response::builder()
                    .status(422)
                    .body(Body::from(format!("Error: {oe:?}"))))
            } else {
                Ok(warp::http::Response::builder()
                    .status(400)
                    .body(Body::from(&b"Request error"[..])))
            }
        }
    }
}

#[allow(clippy::unused_async)]
async fn discover(
    config: String,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    Ok(warp::http::Response::builder()
        .status(200)
        .body(Vec::from(config)))
}

fn with_ohttp(
    ohttp: Arc<Mutex<OhttpServer>>,
) -> impl Filter<Extract = (Arc<Mutex<OhttpServer>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || Arc::clone(&ohttp))
}

async fn import_config(kms: &str, maa: &str) -> Res<KeyConfig> {
    // Get MAA token from CVM guest attestation library
    let Some(tok) = attest("{}".as_bytes(), 0xffff, maa) else {
        panic!("Failed to get MAA token. You must be root to access TPM.")
    };
    let token = String::from_utf8(tok).unwrap();
    info!("Fetched MAA token: {}", token);

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    // Retrying logic for receipt
    let max_retries = 3;
    let mut retries = 0;
    let key: String;
    let mut kid: u8 = 0;

    loop {
        // Get HPKE private key from Azure KMS
        let response = client
            .post(kms)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        // We may have to wait for receipt to be ready
        if response.status() == 202 {
            if retries < max_retries {
                retries += 1;
                trace!(
                    "Received 202 status code, retrying... (attempt {}/{})",
                    retries, max_retries
                );
                sleep(Duration::from_secs(1)).await;
            } else {
                panic!("Max retries reached, giving up. Cannot reach key management service");
            }
        } else {
            let skr_body = response.text().await?;
            let skr: ExportedKey =
                from_str(&skr_body).expect("Failed to deserialize SKR response. Check KMS version");

            info!(
                "SKR successful, KID={}, Receipt={}, Key={}",
                skr.kid, skr.receipt, skr.key
            );
            key = skr.key;
            break;
        }
    }
    let cwk = hex::decode(&key).expect("Failed to decode hex key");
    let cwk_map: Value = serde_cbor::from_slice(&cwk).expect("Invalid CBOR in key from KMS");
    let mut d = None;

    // Parse the returned CBOR key (in CWK-like format)
    if let Value::Map(map) = cwk_map {
        for (key, value) in map {
            if let Value::Integer(key) = key {
                match key {
                    // key identifier
                    4 => {
                        if let Value::Integer(k) = value {
                            kid = k as u8
                        } else {
                            panic!("Bad KID");
                        }
                    }

                    // private exponent
                    -4 => {
                        if let Value::Bytes(vec) = value {
                            d = Some(vec)
                        } else {
                            panic!("Invalid private key");
                        }
                    }

                    // key type, must be P-384(2)
                    -1 => {
                        if value == Value::Integer(2) {
                        } else {
                            panic!("Bad CBOR key type, expected P-384(2)");
                        }
                    }

                    // Ignore public key (x,y) as we recompute it from d anyway
                    -2 | -3 => (),

                    _ => panic!("Unexpected field in exported private key from KMS"),
                };
            };
        }
    } else {
        panic!("Incorrect CBOR encoding in returned private key");
    };

    let (sk, pk) = if let Some(key) = d {
        let s = <hpke::kem::DhP384HkdfSha384 as hpke::Kem>::PrivateKey::from_bytes(&key)
            .expect("Failed to create HPKE private key");
        let p = <hpke::kem::DhP384HkdfSha384 as hpke::Kem>::sk_to_pk(&s);
        (s, p)
    } else {
        panic!("Missing private exponent in key returned from KMS");
    };

    let config = KeyConfig::import_p384(
        kid,
        Kem::P384Sha384,
        sk,
        pk,
        vec![
            SymmetricSuite::new(Kdf::HkdfSha384, Aead::Aes256Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
        ],
    )?;

    Ok(config)
}

#[tokio::main]
async fn main() -> Res<()> {
    let args = Args::parse();
    ::ohttp::init();
    env_logger::try_init().unwrap();

    let config = if args.attest {
        let kms_url = &args.kms_url.clone().unwrap_or(DEFAULT_KMS_URL.to_string());
        let maa_url = &args.maa_url.clone().unwrap_or(DEFAULT_MAA_URL.to_string());
        import_config(maa_url, kms_url).await?
    } else {
        KeyConfig::new(
            0,
            Kem::X25519Sha256,
            vec![
                SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
                SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
            ],
        )?
    };

    let ohttp = OhttpServer::new(config)?;
    let config = hex::encode(KeyConfig::encode_list(&[ohttp.config()])?);
    info!("Config: {}", config);

    let mode = args.mode();
    let target = args.target;

    let score = warp::post()
        .and(warp::path::path("score"))
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(with_ohttp(Arc::new(Mutex::new(ohttp))))
        .and(warp::any().map(move || target.clone()))
        .and(warp::any().map(move || mode))
        .and_then(score);

    let discover = warp::get()
        .and(warp::path("discover"))
        .and(warp::path::end())
        .and(warp::any().map(move || config.clone()))
        .and_then(discover);

    let routes = score.or(discover);

    warp::serve(routes)
        .run(args.address)
        .await;

    Ok(())
}
