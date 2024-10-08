use bhttp::{Message, Mode};
use clap::Parser;
use futures_util::{stream::unfold, StreamExt};
use log::{info, trace};
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
struct HexArg(Vec<u8>);
impl FromStr for HexArg {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s).map(HexArg)
    }
}
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

    /// List of headers in the outer request
    #[arg(long, short = 'H')]
    headers: Option<Vec<String>>,

    /// List of headers in the outer request
    #[arg(long, short = 'F')]
    form_fields: Option<Vec<String>>,

    /// List of headers in the outer request
    #[arg(long, short = 'O')]
    outer_headers: Option<Vec<String>>,

    /// List of headers in the outer request
    #[arg(long, short = 'T')]
    token: Option<String>,
}

// Create a multi-part request from a file
fn create_multipart_request(
    target_path: &str,
    headers: Option<Vec<String>>,
    fields: Option<Vec<String>>,
) -> Res<Vec<u8>> {
    // Define boundary for multipart
    let boundary = "----ConfidentialInferencingFormBoundary7MA4YWxkTrZu0gW";

    let mut request = Vec::new();
    write!(&mut request, "POST {target_path} HTTP/1.1\r\n")?;

    if let Some(headers) = headers {
        for header in headers {
            write!(&mut request, "{header}\r\n")?;
            info!("{header}\r\n");
        }
    }

    // Create multipart body
    let mut body = Vec::new();

    if let Some(fields) = fields {
        for field in fields {
            let (name, value) = field.split_once('=').unwrap();
            if value.starts_with('@') {
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

    write!(
        &mut request,
        "Content-Type: multipart/form-data; boundary={boundary}\r\n"
    )?;
    write!(&mut request, "Content-Length: {}\r\n", body.len())?;
    write!(&mut request, "\r\n")?;
    request.append(&mut body);

    Ok(request)
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

#[tokio::main]
async fn main() -> Res<()> {
    let args = Args::parse();
    ::ohttp::init();
    env_logger::try_init().unwrap();

    trace!("================== STEP 1 ==================");

    let request = {
        let form_fields = args.form_fields.clone();
        let headers = args.headers.clone();
        let request = create_multipart_request(&args.target_path, headers, form_fields)?;
        let mut cursor = Cursor::new(request);
        if args.binary {
            Message::read_bhttp(&mut cursor)?
        } else {
            Message::read_http(&mut cursor)?
        }
    };

    let mut request_buf = Vec::new();
    request.write_bhttp(Mode::KnownLength, &mut request_buf)?;

    let ohttp_request = if let Some(kms_cert) = &args.kms_cert {
        let cert = fs::read_to_string(kms_cert)?;
        let kms_url = &args.kms_url.clone().unwrap_or(DEFAULT_KMS_URL.to_string());
        let config = get_kms_config(kms_url.to_string(), &cert).await?;
        from_kms_config(&config, &cert)?
    } else {
        let config = &args.config.clone().expect("Config expected.");
        ohttp::ClientRequest::from_encoded_config_list(config)?
    };

    trace!("================== STEP 2 ==================");

    let (enc_request, client_response) = ohttp_request.encapsulate(&request_buf)?;
    let enc_request_len = enc_request.len();
    info!(
        "Sending encrypted OHTTP request to {}: {}...{}",
        args.url,
        hex::encode(&enc_request[..3]),
        hex::encode(&enc_request[enc_request_len-3..]),
    );

    let client = reqwest::ClientBuilder::new().build()?;

    let tokenstr = args.token.as_ref().map_or("None", |s| s.as_str());

    let mut builder = client
        .post(&args.url)
        .header("content-type", "message/ohttp-chunked-req")
        .header(AUTHORIZATION, format!("Bearer {tokenstr}"));

    // Add outer headers
    info!("Outer request headers:");
    let outer_headers = args.outer_headers.clone();
    if let Some(headers) = outer_headers {
        for header in headers {
            let (key, value) = header.split_once(':').unwrap();
            info!("Adding {key}: {value}");
            builder = builder.header(key, value);
        }
    }

    let response = builder.body(enc_request).send().await?.error_for_status()?;

    info!("response status: {}\n", response.status());
    info!("Response headers:");
    for (key, value) in response.headers() {
        info!(
            "{}: {}",
            key,
            std::str::from_utf8(value.as_bytes()).unwrap()
        );
    }

    let mut output: Box<dyn io::Write> = if let Some(outfile) = &args.output {
        Box::new(File::open(outfile)?)
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
                println!("Error in stream {e}")
            }
        }
    }
    Ok(())
}
