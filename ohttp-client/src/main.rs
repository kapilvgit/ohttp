use bhttp::{Message, Mode};
use clap::Parser;
use futures_util::{stream::unfold, StreamExt};
use ohttp::ClientRequest;
use reqwest::{header::AUTHORIZATION, Client};
use serde::Deserialize;
use std::{
    fs::{self, File},
    io::{self, Cursor, Read, Write},
    ops::Deref,
    path::PathBuf,
    str::FromStr,
};
use tracing::{error, info, trace};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

const DEFAULT_KMS_URL: &str = "https://acceu-aml-504.confidential-ledger.azure.com";

#[derive(Debug, Clone)]
/// This allows a `HexArg` to be created from a string slice (`&str`) by decoding
/// the string as hexadecimal.
struct HexArg(Vec<u8>);
impl FromStr for HexArg {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s).map(HexArg)
    }
}
/// This allows `HexArg` instances to be dereferenced to a slice of bytes (`[u8]`).
impl Deref for HexArg {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Parser)]
#[command(version = "0.1", about = "Make an oblivious HTTP request.")]
struct Args {
    /// The URL of an oblivious proxy resource.
    /// If you use an oblivious request resource, this also works, though
    /// you don't get any of the privacy guarantees.
    url: String,

    /// Target path of the oblivious resource
    #[arg(long, short = 'p')]
    target_path: String,

    /// key configuration
    #[arg(long, short = 'c')]
    config: Option<HexArg>,

    /// json containing the key configuration along with proof
    #[arg(long, short = 'f')]
    kms_url: Option<String>,

    /// Trusted KMS service certificate
    #[arg(long, short = 'k')]
    kms_cert: Option<PathBuf>,

    /// Where to write response content.
    /// If you omit this, output is written to `stdout`.
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    /// Read and write as binary HTTP messages instead of text.
    #[arg(long, short = 'b')]
    binary: bool,

    /// When creating message/bhttp, use the indeterminate-length form.
    #[arg(long, short = 'n', alias = "indefinite")]
    indeterminate: bool,

    /// List of headers in the inner request
    #[arg(long, short = 'H')]
    headers: Option<Vec<String>>,

    /// List of fields in the inner request
    #[arg(long, short = 'F')]
    form_fields: Option<Vec<String>>,

    /// List of headers in the outer request
    #[arg(long, short = 'O')]
    outer_headers: Option<Vec<String>>,

    /// Token for the outer request
    #[arg(long, short = 'T')]
    token: Option<String>,
}

/// Writes the request line for an HTTP POST request to the provided buffer.
/// The request line follows the format:
/// `POST {target_path} HTTP/1.1\r\n`.
fn write_post_request_line(request: &mut Vec<u8>, target_path: &str) -> Res<()> {
    write!(request, "POST {target_path} HTTP/1.1\r\n")?;
    Ok(())
}

/// Appends HTTP headers to the provided request buffer.
fn append_headers(request: &mut Vec<u8>, headers: &Option<Vec<String>>) -> Res<()> {
    if let Some(headers) = headers {
        for header in headers {
            write!(request, "{header}\r\n")?;
            info!("{header}\r\n");
        }
    }
    Ok(())
}

/// Creates a multipart/form-data body for an HTTP request.
/// Structure of multipart body -
///
///      ---------------------------boundaryString
///      Content-Disposition: form-data; name="field1"
///
///      value1
///      ---------------------------boundaryString
///      Content-Disposition: form-data; name="file"; filename="example.txt"
///      Content-Type: text/plain
///
///      ... contents of the file ...
///      ---------------------------boundaryString
fn create_multipart_body(fields: &Option<Vec<String>>, boundary: &str) -> Res<Vec<u8>> {
    let mut body = Vec::new();

    if let Some(fields) = fields {
        for field in fields {
            let (name, value) = field.split_once('=').unwrap();
            if value.starts_with('@') {
                // If the value starts with '@', it is treated as a file path.
                let filename = value.strip_prefix('@').unwrap();
                let mut file = File::open(filename)?;
                let mut file_contents = Vec::new();
                file.read_to_end(&mut file_contents)?;

                // Add the file
                write!(
                    &mut body,
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: audio/mp3\r\n\r\n"
                )?;
                body.extend_from_slice(&file_contents);
            } else {
                write!(
                    &mut body,
                    "\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
                )?;
                write!(&mut body, "{value}")?;
            }
            write!(&mut body, "\r\n--{boundary}--\r\n")?;
        }
    }

    Ok(body)
}

/// Writes the headers for a multipart/form-data HTTP request to the provided buffer.
///      Content-Type: multipart/form-data; boundary=---------------------------boundaryString
///      Content-Length: 12345
fn write_multipart_headers(request: &mut Vec<u8>, boundary: &str, body_len: usize) -> Res<()> {
    write!(
        request,
        "Content-Type: multipart/form-data; boundary={boundary}\r\n"
    )?;
    write!(request, "Content-Length: {}\r\n", body_len)?;
    write!(request, "\r\n")?;
    Ok(())
}

/// Creates an http multipart message.
///      Content-Type: multipart/form-data; boundary=---------------------------boundaryString
///      Content-Length: 12345
///
///      ---------------------------boundaryString
///      Content-Disposition: form-data; name="field1"
///
///      value1
///      ---------------------------boundaryString
///      Content-Disposition: form-data; name="file"; filename="example.txt"
///      Content-Type: text/plain
///
///      ... contents of the file ...
///      ---------------------------boundaryString
fn create_multipart_request(
    target_path: &str,
    headers: &Option<Vec<String>>,
    fields: &Option<Vec<String>>,
) -> Res<Vec<u8>> {
    // Define boundary for multipart
    let boundary = "----ConfidentialInferencingFormBoundary7MA4YWxkTrZu0gW";

    // Create a POST request for target target_path
    let mut request = Vec::new();
    write_post_request_line(&mut request, target_path)?;
    append_headers(&mut request, headers)?;

    // Create multipart body
    let mut body = create_multipart_body(fields, boundary)?;

    // Append multipart headers
    write_multipart_headers(&mut request, boundary, body.len())?;

    // Append body to the request
    request.append(&mut body);

    Ok(request)
}

/// Prepares a http message based on the `is_bhttp` flag and other parameters.
fn create_request_buffer(
    is_bhttp: bool,
    target_path: &str,
    headers: &Option<Vec<String>>,
    form_fields: &Option<Vec<String>>,
) -> Res<Vec<u8>> {
    let request = create_multipart_request(target_path, headers, form_fields)?;
    let mut cursor = Cursor::new(request);

    // If `is_bhttp` is `true`, it reads a BHTTP message using `Message::read_bhttp`.
    //  Otherwise, it reads a standard HTTP message using `Message::read_http`.
    let request = if is_bhttp {
        Message::read_bhttp(&mut cursor)?
    } else {
        Message::read_http(&mut cursor)?
    };

    let mut request_buf = Vec::new();
    request.write_bhttp(Mode::KnownLength, &mut request_buf)?;
    Ok(request_buf)
}

// Get key configuration from KMS
async fn get_kms_config(kms_url: String, cert: &str) -> Res<String> {
    // Create a client with the CA certificate
    let client = Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.as_bytes())?)
        .build()?;

    info!("Contacting key management service at {kms_url}...");

    // Make the GET request
    let response = client
        .get(kms_url + "/listpubkeys")
        .send()
        .await?
        .error_for_status()?;

    let body = response.text().await?;
    assert!(!body.is_empty());
    Ok(body)
}

#[derive(Deserialize)]
struct KmsKeyConfiguration {
    #[serde(rename = "publicKey")]
    key_config: String,
    receipt: String,
}

/// Reads a json containing key configurations with receipts and constructs
/// a single use client sender from the first supported configuration.
pub fn create_request_from_kms_config(config: &str, cert: &str) -> Res<ClientRequest> {
    let mut kms_configs: Vec<KmsKeyConfiguration> = serde_json::from_str(config)?;

    let kms_config = match kms_configs.pop() {
        Some(config) => config,
        None => return Err("No KMS configuration found".into()),
    };

    info!("{}", "Establishing trust in key management service...");
    let _ = verifier::verify(&kms_config.receipt, cert)?;
    info!(
        "{}",
        "The receipt for the generation of the OHTTP key is valid."
    );

    let encoded_config = hex::decode(&kms_config.key_config)?;
    Ok(ClientRequest::from_encoded_config(&encoded_config)?)
}

/// Creates an OHTTP client from the static config provided in Args.
///
fn create_request_handler(config: &Option<HexArg>) -> Res<ohttp::ClientRequest> {
    let config = config.clone().expect("Config expected.");
    Ok(ohttp::ClientRequest::from_encoded_config_list(&config)?)
}

/// Creates an OHTTP client from KMS.
///
async fn create_request_handler_from_kms(
    kms_cert: &PathBuf,
    kms_url: &Option<String>,
) -> Res<ohttp::ClientRequest> {
    let cert = fs::read_to_string(kms_cert)?;
    let url = kms_url
        .clone()
        .unwrap_or_else(|| DEFAULT_KMS_URL.to_string());
    let config = get_kms_config(url.to_string(), &cert).await?;
    create_request_from_kms_config(&config, &cert)
}

async fn post_request(
    url: &String,
    outer_headers: &Option<Vec<String>>,
    token: &Option<String>,
    enc_request: Vec<u8>,
) -> Res<reqwest::Response> {
    let client = reqwest::ClientBuilder::new().build()?;

    let tokenstr = token.as_ref().map_or("None", |s| s.as_str());

    let mut builder = client
        .post(url)
        .header("content-type", "message/ohttp-chunked-req")
        .header(AUTHORIZATION, format!("Bearer {tokenstr}"));

    // Add outer headers
    trace!("Outer request headers:");
    let outer_headers = outer_headers.clone();
    if let Some(headers) = outer_headers {
        for header in headers {
            let (key, value) = header.split_once(':').unwrap();
            trace!("Adding {key}: {value}");
            builder = builder.header(key, value);
        }
    }

    let response = builder.body(enc_request).send().await?.error_for_status()?;
    trace!("response status: {}\n", response.status());
    trace!("Response headers:");
    for (key, value) in response.headers() {
        trace!(
            "{}: {}",
            key,
            std::str::from_utf8(value.as_bytes()).unwrap()
        );
    }

    Ok(response)
}

/// Decapsulate the http response
/// The response can be saved to a file or printed to stdout, based on the value of args.output
async fn handle_response(
    response: reqwest::Response,
    client_response: ohttp::ClientResponse,
    output: &Option<PathBuf>,
) -> Res<()> {
    let mut output: Box<dyn io::Write> = if let Some(outfile) = output {
        match File::create(outfile) {
            Ok(file) => Box::new(file),
            Err(e) => {
                error!("Error opening output file: {}", e);
                return Err(Box::new(e));
            }
        }
    } else {
        Box::new(std::io::stdout())
    };

    let stream = Box::pin(unfold(response, |mut response| async move {
        match response.chunk().await {
            Ok(Some(chunk)) => Some((Ok(chunk.to_vec()), response)),
            _ => None,
        }
    }));

    let mut stream = client_response.decapsulate_stream(stream).await;
    while let Some(result) = stream.next().await {
        match result {
            Ok(chunk) => {
                output.write_all("\n".as_bytes())?;
                output.write_all(&chunk)?;
            }
            Err(e) => {
                error!("Error in stream {e}")
            }
        }
    }

    Ok(())
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

    //  Create ohttp request buffer
    let request_buffer = match create_request_buffer(
        args.binary,
        &args.target_path,
        &args.headers,
        &args.form_fields,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("{e}");
            return Err(e);
        }
    };

    trace!("Created the ohttp request buffer");

    //  create the OHTTP request handler using the KMS or the static config file
    let result = if let Some(kms_cert) = &args.kms_cert {
        create_request_handler_from_kms(kms_cert, &args.kms_url).await
    } else {
        create_request_handler(&args.config)
    };
    let request_handler = match result {
        Ok(request) => request,
        Err(e) => {
            error!("{e}");
            return Err(e);
        }
    };
    trace!("Created ohttp client request handler");

    // Encapsulate the http buffer using the OHTTP request
    let (enc_request, response_handler) = match request_handler.encapsulate(&request_buffer) {
        Ok(result) => result,
        Err(e) => {
            error!("{e}");
            return Err(Box::new(e));
        }
    };
    trace!(
        "Encapsulated the OHTTP request {}",
        hex::encode(&enc_request[0..60])
    );

    // Post the encapsulated ohttp request buffer to args.url
    let response =
        match post_request(&args.url, &args.outer_headers, &args.token, enc_request).await {
            Ok(response) => response,
            Err(e) => {
                error!("{e}");
                return Err(e);
            }
        };
    trace!("Posted the OHTTP request to {}", args.url);

    // decapsulate and output the http response
    if let Err(e) = handle_response(response, response_handler, &args.output).await {
        error!("{e}");
        return Err(e);
    }

    Ok(())
}
