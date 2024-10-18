#![deny(clippy::pedantic)]

use std::{io::Cursor, net::SocketAddr, sync::Arc};

use lazy_static::lazy_static;
use moka::future::Cache;

use futures_util::stream::unfold;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method, Response, Url,
};

use bhttp::{Message, Mode};
use clap::Parser;
use ohttp::{
    hpke::{Aead, Kdf, Kem},
    Error, KeyConfig, Server as OhttpServer, ServerResponse, SymmetricSuite,
};
use warp::{hyper::Body, Filter};

use tokio::time::{sleep, Duration};

use cgpuvm_attest::attest;
use reqwest::Client;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

use serde_cbor::Value;
use serde_json::from_str;

use hpke::Deserializable;
use serde::Deserialize;

use tracing::{error, info, trace};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[derive(Deserialize)]
struct ExportedKey {
    kid: u8,
    key: String,
    receipt: String,
}

const DEFAULT_KMS_URL: &str = "https://acceu-aml-504.confidential-ledger.azure.com/key";
const DEFAULT_MAA_URL: &str = "https://sharedeus2.eus2.attest.azure.net";
const FILTERED_RESPONSE_HEADERS: [&str; 2] = ["content-type", "content-length"];

#[derive(Debug, Parser, Clone)]
#[command(name = "ohttp-server", about = "Serve oblivious HTTP requests.")]
struct Args {
    /// The address to bind to.
    // #[arg(default_value = "127.0.0.1:9443")]
    #[arg(default_value = "0.0.0.0:9443")]
    address: SocketAddr,

    /// When creating message/bhttp, use the indeterminate-length form.
    #[arg(long, short = 'n', alias = "indefinite")]
    indeterminate: bool,

    /// Target server
    #[arg(long, short = 't', default_value = "http://127.0.0.1:8000")]
    target: Url,

    /// Use locally generated key, for testing without KMS
    #[arg(long, short = 'l')]
    local_key: bool,

    /// MAA endpoint
    #[arg(long, short = 'm')]
    maa_url: Option<String>,

    /// KMS endpoint
    #[arg(long, short = 's')]
    kms_url: Option<String>,

    #[arg(long, short = 'i')]
    inject_request_headers: Vec<String>,
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

lazy_static! {
    static ref cache: Arc<Cache<i32, (KeyConfig, String)>> = Arc::new(
        Cache::builder()
            .time_to_live(Duration::from_secs(24 * 60 * 60))
            .build()
    );
}

fn parse_cbor_key(key: &str, kid: i32) -> Res<(Option<Vec<u8>>, u8)> {
    let cwk = hex::decode(key)?;
    let cwk_map: Value = serde_cbor::from_slice(&cwk)?;
    let mut d = None;
    let mut returned_kid: u8 = 0;
    if let Value::Map(map) = cwk_map {
        for (key, value) in map {
            if let Value::Integer(key) = key {
                match key {
                    // key identifier
                    4 => {
                        if let Value::Integer(k) = value {
                            returned_kid = u8::try_from(k).unwrap();
                            if kid >= 0 && i32::from(returned_kid) != kid {
                                error!("{}", Error::KMSKeyIdMismatch(returned_kid, kid));
                                return Err(Box::new(Error::KMSKeyIdMismatch(returned_kid, kid)));
                            }
                        } else {
                            error!("{}", Error::KMSKeyId);
                            return Err(Box::new(Error::KMSKeyId));
                        }
                    }

                    // private exponent
                    -4 => {
                        if let Value::Bytes(vec) = value {
                            d = Some(vec);
                        } else {
                            error!("{}", Error::KMSExponent);
                            return Err(Box::new(Error::KMSExponent));
                        }
                    }

                    // key type, must be P-384(2)
                    -1 => {
                        if value == Value::Integer(2) {
                        } else {
                            error!("{}", Error::KMSCBORKeyType);
                            return Err(Box::new(Error::KMSCBORKeyType));
                        }
                    }

                    // Ignore public key (x,y) as we recompute it from d anyway
                    -2 | -3 => (),

                    _ => {
                        error!("{}", Error::KMSField);
                        return Err(Box::new(Error::KMSField));
                    }
                };
            };
        }
    } else {
        error!("{}", Error::KMSCBOREncoding);
        return Err(Box::new(Error::KMSCBOREncoding));
    };
    Ok((d, returned_kid))
}

/// Fetches the MAA token from the CVM guest attestation library.
///
fn fetch_maa_token(maa: &str) -> Res<String> {
    // Get MAA token from CVM guest attestation library
    info!("Fetching MAA token from {maa}");
    let token = attest("{}".as_bytes(), 0xffff, maa)?;

    let token = String::from_utf8(token).unwrap();
    trace!("{token}");
    Ok(token)
}

/// Retrieves the HPKE private key from Azure KMS.
///
async fn get_hpke_private_key_from_kms(kms: &str, kid: i32, token: &str) -> Res<String> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    // Retrying logic for receipt
    let max_retries = 3;
    let mut retries = 0;

    loop {
        // kid < 0 will get the latest, this is used by the discover endpoint
        let url = if kid >= 0 {
            format!("{kms}?kid={kid}")
        } else {
            kms.to_owned()
        };
        info!("Sending SKR request to {url}");

        // Get HPKE private key from Azure KMS
        // FIXME(adl) kid should be an input of the SKR request
        let response = client
            .post(url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;

        // We may have to wait for receipt to be ready
        match response.status().as_u16() {
            202 => {
                if retries < max_retries {
                    retries += 1;
                    trace!(
                        "Received 202 status code, retrying... (attempt {}/{})",
                        retries,
                        max_retries
                    );
                    sleep(Duration::from_secs(1)).await;
                } else {
                    error!("{}", Error::KMSUnreachable);
                    return Err(Box::new(Error::KMSUnreachable));
                }
            }
            200 => {
                let skr_body = response.text().await?;
                info!("SKR successful {}", skr_body);

                let skr: ExportedKey = from_str(&skr_body)?;
                trace!(
                    "requested KID={}, returned KID={}, Receipt={}",
                    kid,
                    skr.kid,
                    skr.receipt
                );

                if kid >= 0 && i32::from(skr.kid) != kid {
                    error!("{}", Error::KMSKeyIdMismatch(skr.kid, kid));
                    return Err(Box::new(Error::KMSKeyIdMismatch(skr.kid, kid)));
                }

                return Ok(skr.key);
            }
            e => {
                error!("{}", Error::KMSUnexpected(e));
                return Err(Box::new(Error::KMSUnexpected(e)));
            }
        }
    }
}

async fn import_config(maa: &str, kms: &str, kid: i32) -> Res<(KeyConfig, String)> {
    // Check if the key configuration is in cache
    if let Some((config, token)) = cache.get(&kid).await {
        info!("Found OHTTP configuration for KID {kid} in cache.");
        return Ok((config, token));
    }

    // Get MAA token from CVM guest attestation library
    let token = fetch_maa_token(maa)?;

    let key = get_hpke_private_key_from_kms(kms, kid, &token).await?;

    let (d, returned_kid) = parse_cbor_key(&key, kid)?;

    let sk = match d {
        Some(key) => <hpke::kem::DhP384HkdfSha384 as hpke::Kem>::PrivateKey::from_bytes(&key),
        None => Err("Private key missing from SKR response")?,
    }?;
    let pk = <hpke::kem::DhP384HkdfSha384 as hpke::Kem>::sk_to_pk(&sk);

    let config = KeyConfig::import_p384(
        returned_kid,
        Kem::P384Sha384,
        sk,
        pk,
        vec![
            SymmetricSuite::new(Kdf::HkdfSha384, Aead::Aes256Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
        ],
    )?;

    cache.insert(kid, (config.clone(), token.clone())).await;
    Ok((config, token))
}

/// Copies headers from the encapsulated request and logs them.
///
fn get_headers_from_request(bin_request: &Message) -> HeaderMap {
    info!("Inner request headers");
    let mut headers = HeaderMap::new();
    for field in bin_request.header().fields() {
        info!(
            "    {}: {}",
            std::str::from_utf8(field.name()).unwrap(),
            std::str::from_utf8(field.value()).unwrap()
        );

        headers.append(
            HeaderName::from_bytes(field.name()).unwrap(),
            HeaderValue::from_bytes(field.value()).unwrap(),
        );
    }
    headers
}

async fn generate_reply(
    ohttp: &OhttpServer,
    inject_headers: HeaderMap,
    enc_request: &[u8],
    target: Url,
    _mode: Mode,
) -> Res<(Response, ServerResponse)> {
    let (request, server_response) = ohttp.decapsulate(enc_request)?;
    let bin_request = Message::read_bhttp(&mut Cursor::new(&request[..]))?;

    let method: Method = if let Some(method_bytes) = bin_request.control().method() {
        Method::from_bytes(method_bytes)?
    } else {
        Method::GET
    };

    // Copy headers from the encapsulated request
    let mut headers = get_headers_from_request(&bin_request);

    // Inject additional headers from the outer request
    if !inject_headers.is_empty() {
        info!("Appending injected headers");
        for (key, value) in inject_headers {
            if let Some(key) = key {
                info!("    {}: {}", key.as_str(), value.to_str().unwrap());
                headers.append(key, value);
            }
        }
    };

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

// Compute the set of headers that need to be injected into the inner request
fn compute_injected_headers(headers: &HeaderMap, keys: Vec<String>) -> HeaderMap {
    let mut result = HeaderMap::new();
    for key in keys {
        if let Ok(header_name) = HeaderName::try_from(key) {
            if let Some(value) = headers.get(&header_name) {
                result.insert(header_name, value.clone());
            }
        }
    }
    result
}

async fn score(
    headers: warp::hyper::HeaderMap,
    body: warp::hyper::body::Bytes,
    args: Arc<Args>,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    let target = args.target.clone();
    info!("Received encapsulated score request for target {}", target);

    info!("Request headers length = {}", headers.len());
    let mut return_token = false;
    for (key, value) in &headers {
        info!("    {}: {}", key, value.to_str().unwrap());
        if key == "x-attestation-token" {
            return_token = true;
        }
    }

    // The KID is normally the first byte of the request
    let kid = match body.first().copied() {
        None => -1,
        Some(kid) => i32::from(kid),
    };

    let maa_url = args.maa_url.clone().unwrap_or(DEFAULT_MAA_URL.to_string());
    let kms_url = args.kms_url.clone().unwrap_or(DEFAULT_KMS_URL.to_string());
    let ohttp = if args.local_key && kid != 0 {
        info!("Ignoring non-0 KID {kid} with local keying configuration");
        None
    } else if let Ok((config, token)) = import_config(&maa_url, &kms_url, kid).await {
        match OhttpServer::new(config) {
            Ok(ohttp) => Some((ohttp, token)),
            _ => None,
        }
    } else {
        error!("Failed to load KID {kid} from KMS");
        None
    };

    match ohttp {
      None => Ok(warp::http::Response::builder()
                .status(500)
                .body(Body::from(&b"Failed to get or load the OHTTP configuration from local cache or key management service."[..]))),

      Some((ohttp,token)) => {
        let inject_request_headers = args.inject_request_headers.clone();
        info!(
            "Request inject headers length = {}",
            inject_request_headers.len()
        );
        for key in &inject_request_headers {
            info!("    {}", key);
        }

        let inject_headers = compute_injected_headers(&headers, inject_request_headers);
        info!("Injected headers length = {}", inject_headers.len());
        for (key, value) in &inject_headers {
            info!("    {}: {}", key, value.to_str().unwrap());
        }

        let mode = args.mode();
        let reply = generate_reply(&ohttp, inject_headers, &body[..], target, mode).await;

        match reply {
            Ok((response, server_response)) => {
                let mut builder =
                    warp::http::Response::builder().header("Content-Type", "message/ohttp-chunked-res");


                // Add HTTP header with MAA token, for client auditing.
                if return_token {
                    builder = builder.header(HeaderName::from_static("x-attestation-token"), token.clone());
                }

                // Move headers from the inner response into the outer response
                info!("Response headers:");
                for (key, value) in response.headers() {
                    if !FILTERED_RESPONSE_HEADERS
                        .iter()
                        .any(|h| h.eq_ignore_ascii_case(key.as_str()))
                    {
                        info!(
                            "    {}: {}",
                            key,
                            std::str::from_utf8(value.as_bytes()).unwrap()
                        );
                        builder = builder.header(key.as_str(), value.as_bytes());
                    }
                }

                let stream = Box::pin(unfold(response, |mut response| async move {
                    match response.chunk().await {
                        Ok(Some(chunk)) => {
                            Some((Ok::<Vec<u8>, ohttp::Error>(chunk.to_vec()), response))
                        }
                        _ => None,
                    }
                }));

                let stream = server_response.encapsulate_stream(stream);
                Ok(builder.body(Body::wrap_stream(stream)))
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
    }
}

async fn discover(args: Arc<Args>) -> Result<impl warp::Reply, std::convert::Infallible> {
    let kms_url = &args.kms_url.clone().unwrap_or(DEFAULT_KMS_URL.to_string());
    let maa_url = &args.maa_url.clone().unwrap_or(DEFAULT_MAA_URL.to_string());

    // The discovery endpoint is only enabled for local testing
    if !args.local_key {
        return Ok(warp::http::Response::builder()
            .status(404)
            .body(Body::from(&b"Not found"[..])));
    }

    match import_config(maa_url, kms_url, 0).await {
        Ok((config, _)) => match KeyConfig::encode_list(&[config]) {
            Ok(list) => {
                let hex = hex::encode(list);
                trace!("Discover config: {}", hex);

                Ok(warp::http::Response::builder()
                    .status(200)
                    .body(Vec::from(hex).into()))
            }
            Err(_e) => Ok(warp::http::Response::builder().status(500).body(Body::from(
                &b"Invalid key configuration (check KeyConfig written to initial cache)"[..],
            ))),
        },
        Err(_e) => Ok(warp::http::Response::builder().status(500).body(Body::from(
            &b"KID 0 missing from cache (should be impossible with local keying)"[..],
        ))),
    }
}

#[tokio::main]
async fn main() -> Res<()> {
    // Build a simple subscriber that outputs to stdout
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_file(true)
        .with_line_number(true)
        .json()
        .finish();

    // Set the subscriber as global default
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    ::ohttp::init();

    let args = Args::parse();
    let address = args.address;
    let is_local = args.local_key;
    // Generate a fresh key for local testing. KID is set to 0.
    if is_local {
        let config = KeyConfig::new(
            0,
            Kem::P384Sha384,
            vec![
                SymmetricSuite::new(Kdf::HkdfSha384, Aead::Aes256Gcm),
                SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
                SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
            ],
        )
        .map_err(|e| {
            error!("{e}");
            e
        })?;
        cache.insert(0, (config, String::new())).await;
    }

    let argsc = Arc::new(args);
    let args1 = Arc::clone(&argsc);
    let score = warp::post()
        .and(warp::path::path("score"))
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(warp::body::bytes())
        .and(warp::any().map(move || Arc::clone(&args1)))
        .and_then(score);

    let args2 = Arc::clone(&argsc);
    let discover = warp::get()
        .and(warp::path("discover"))
        .and(warp::path::end())
        .and(warp::any().map(move || Arc::clone(&args2)))
        .and_then(discover);

    let routes = score.or(discover);
    warp::serve(routes).run(address).await;

    Ok(())
}
