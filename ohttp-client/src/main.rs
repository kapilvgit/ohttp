use bhttp::{Message, Mode};
use clap::Parser;
use futures_util::{stream::unfold, StreamExt};
use log::{error, info, trace};
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
fn prepare_http_request(
    is_bhttp: bool,
    target_path: &String,
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
    if body.is_empty() {
        return Err("Received empty response from KMS".into());
    }
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
pub fn from_kms_config(config: &str, cert: &str) -> Res<ClientRequest> {
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

/// Creates an OHTTP client request based on the provided arguments.
///
/// This asynchronous function constructs an `ohttp::ClientRequest` by either
/// fetching and validating a KMS configuration or using a predefined configuration.
/// If a KMS certificate is provided, it reads the certificate, retrieves the KMS URL,
/// fetches the KMS configuration, and validates it. If no KMS certificate is provided,
/// it uses the encoded configuration list from the arguments.
///
/// # Arguments
///
/// * `args` - A reference to an `Args` struct containing the necessary parameters.
///
/// # Returns
///
/// This function returns a `Res<ohttp::ClientRequest>`, which is a type alias for
/// `Result<ohttp::ClientRequest, Box<dyn std::error::Error>>`. It returns an
/// `ohttp::ClientRequest` if successful, or an error if any operation fails.
///
/// # Errors
///
/// This function will return an error if:
/// - The KMS certificate cannot be read.
/// - The KMS configuration cannot be fetched or validated.
/// - The encoded configuration list is missing or invalid.
///
async fn create_ohttp_client_request(args: &Args) -> Res<ohttp::ClientRequest> {
    if let Some(kms_cert) = &args.kms_cert {
        let cert = fs::read_to_string(kms_cert)?;
        let kms_url = &args.kms_url.clone().unwrap_or(DEFAULT_KMS_URL.to_string());
        let config = get_kms_config(kms_url.to_string(), &cert).await?;
        from_kms_config(&config, &cert)
    } else {
        let config = &args.config.clone().expect("Config expected.");
        Ok(ohttp::ClientRequest::from_encoded_config_list(config)?)
    }
}

async fn send_request(args: &Args, enc_request: Vec<u8>) -> Res<reqwest::Response> {
    let client = reqwest::ClientBuilder::new().build()?;

    let tokenstr = args.token.as_ref().map_or("None", |s| s.as_str());

    let mut builder = client
        .post(&args.url)
        .header("content-type", "message/ohttp-chunked-req")
        .header(AUTHORIZATION, format!("Bearer {tokenstr}"));

    // Add outer headers
    trace!("Outer request headers:");
    let outer_headers = args.outer_headers.clone();
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

async fn handle_response(
    response: reqwest::Response,
    client_response: ohttp::ClientResponse,
    args: &Args,
) -> Res<()> {
    let mut output: Box<dyn io::Write> = if let Some(outfile) = &args.output {
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
    ::ohttp::init();

    let args = Args::parse();

    //  Prepare http request buffer
    let request = match prepare_http_request(
        args.binary,
        &args.target_path,
        &args.headers,
        &args.form_fields,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Error preparing request: {}", e);
            return Err(e);
        }
    };
    trace!("Prepared the request buffer");

    // Create ohttp client request
    let ohttp_request = match create_ohttp_client_request(&args).await {
        Ok(request) => request,
        Err(e) => {
            error!("Error preparing OHTTP request: {}", e);
            return Err(e);
        }
    };
    trace!("Created ohttp client request");

    let (enc_request, client_response) = match ohttp_request.encapsulate(&request) {
        Ok(result) => result,
        Err(e) => {
            error!("Error encapsulating request: {}", e);
            return Err(Box::new(e));
        }
    };
    trace!(
        "Encapsulated the OHTTP request to be sent to {}: {}",
        args.url,
        hex::encode(&enc_request[0..60])
    );

    let response = match send_request(&args, enc_request).await {
        Ok(response) => response,
        Err(e) => {
            error!("Error sending request: {}", e);
            return Err(e);
        }
    };

    match handle_response(response, client_response, &args).await {
        Ok(_) => (),
        Err(e) => {
            error!("Error handling response: {}", e);
            return Err(e);
        }
    }

    Ok(())
}
