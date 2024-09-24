#![deny(clippy::pedantic)]

use bhttp::{Message, Mode};
use std::{
    fs::{self, File}, io::{self, Read, Write}, ops::Deref, path::PathBuf, str::FromStr
};
use std::io::Cursor;
use structopt::StructOpt;
use reqwest::Client;
use futures_util::stream::unfold;
use futures_util::StreamExt;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

const DEFAULT_KMS_URL: &str ="https://acceu-aml-504.confidential-ledger.azure.com";

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

use log::info;

#[derive(Debug, StructOpt)]
#[structopt(name = "ohttp-client", about = "Make an oblivious HTTP request.")]
struct Args {
    /// The URL of an oblivious proxy resource.
    /// If you use an oblivious request resource, this also works, though
    /// you don't get any of the privacy guarantees.
    url: String,

    /// Target path of the oblivious resource
    #[structopt(long, short = "p")]
    target_path: String,

    /// key configuration
    #[structopt(long, short = "c")]
    config: Option<HexArg>,

    /// json containing the key configuration along with proof
    #[structopt(long, short = "f")]
    kms_url: Option<String>,

    /// Trusted KMS service certificate
    #[structopt(long, short = "k")]
    kms_cert: Option<PathBuf>,

    /// Where to read request content.
    /// If you omit this, input is read from `stdin`.
    #[structopt(long, short = "i")]
    input: Option<PathBuf>,

    /// Where to write response content.
    /// If you omit this, output is written to `stdout`.
    #[structopt(long, short = "o")]
    output: Option<PathBuf>,

    /// Read and write as binary HTTP messages instead of text.
    #[structopt(long, short = "b")]
    binary: bool,

    /// Enable override for the trust store.
    #[structopt(long)]
    trust: Option<PathBuf>,

    #[structopt(long, short = "a")]
    api_key: Option<String>
}

// Create a multi-part request from a file
fn create_multipart_request(target_path: &str, file: &PathBuf) -> Res<Vec<u8>> {
    // Define boundary for multipart
    let boundary = "----ConfidentialInferencingFormBoundary7MA4YWxkTrZu0gW";

    // Load audio file
    let mut file = File::open(file)?;
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents)?;

    // Create multipart body
    let mut body = Vec::new();

    // Add the file
    write!(
        &mut body,
        "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.mp3\"\r\nContent-Type: {}\r\n\r\n",
        boundary,
        "audio/mp3"
    )?;
    body.extend_from_slice(&file_contents);
    write!(&mut body, "\r\n--{}--\r\n", boundary)?;

    // Add the response format
    write!(
        &mut body,
        "\r\nContent-Disposition: form-data; name=\"response_format\"\r\n\r\n",
    )?;
    write!(&mut body, "verbose_json")?;
    write!(&mut body, "\r\n--{}--\r\n", boundary)?;

    // Add the model
    write!(
        &mut body,
        "\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n",
    )?;
    write!(&mut body, "whisper-3")?;
    write!(&mut body, "\r\n--{}--\r\n", boundary)?;

    // Add language
    write!(
        &mut body,
        "\r\nContent-Disposition: form-data; name=\"language\"\r\n\r\n",
    )?;
    write!(&mut body, "en")?;
    write!(&mut body, "\r\n--{}--\r\n", boundary)?;
    
    let mut request = Vec::new();
    write!(&mut request, "POST {} HTTP/1.1\r\n", target_path)?;
    write!(&mut request, "openai-internal-authtoken: \"testtoken\"\r\n")?;
    write!(&mut request, "openai-internal-enableasrsupport: \"true\"\r\n")?;
    write!(&mut request, "Content-Type: multipart/form-data; boundary={}\r\n", boundary)?;
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

    println!("Contacting key management service at {}...", kms_url);

    // Make the GET request
    let response = client.get(kms_url + "/listpubkeys")
        .send()
        .await?
        .error_for_status()?;

    let body = response.text().await?;
    assert!(body.len()> 0);
    Ok(body)
}

#[tokio::main]
async fn main() -> Res<()> {
    let args = Args::from_args();
    ::ohttp::init();
    env_logger::try_init().unwrap();

    info!("================== STEP 1 ==================");

    let request = if let Some(infile) = &args.input {
        let request = create_multipart_request(&args.target_path, infile)?;
        let mut cursor = Cursor::new(request);
        if args.binary {
            Message::read_bhttp(&mut cursor)?
        } else {
            Message::read_http(&mut cursor)?
        }
    } else {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        let mut r = io::Cursor::new(buf);
        if args.binary {
            Message::read_bhttp(&mut r)?
        } else {
            Message::read_http(&mut r)?
        }
    };

    let mut request_buf = Vec::new();
    request.write_bhttp(Mode::KnownLength, &mut request_buf)?;

    let ohttp_request = if let Some(kms_cert) = &args.kms_cert {
        let cert = fs::read_to_string(kms_cert)?;
        let kms_url = &args.kms_url.clone().unwrap_or(DEFAULT_KMS_URL.to_string());
        let config = get_kms_config(kms_url.to_string(), &cert).await?;
        ohttp::ClientRequest::from_kms_config(&config, &cert)?
    } else {
        let config = &args.config.clone().expect("Config expected.");
        ohttp::ClientRequest::from_encoded_config_list(config)?
    };

    info!("================== STEP 2 ==================");
    let (enc_request, client_response) = ohttp_request.encapsulate(&request_buf)?;
    info!("Sending encrypted OHTTP request to {}: {}", args.url, hex::encode(&enc_request[0..60]));

    let client = match &args.trust {
        Some(pem) => {
            let mut buf = Vec::new();
            File::open(pem)?.read_to_end(&mut buf)?;
            let cert = reqwest::Certificate::from_pem(buf.as_slice())?;
            reqwest::ClientBuilder::new()
                .danger_accept_invalid_certs(true)
                .add_root_certificate(cert)
                .build()?
        }
        None => reqwest::ClientBuilder::new().danger_accept_invalid_certs(true).build()?,
    };

    let mut builder = client
        .post(&args.url)
        .header("content-type", "message/ohttp-chunked-req");

    if let Some(key) = &args.api_key {
        builder = builder.header("api-key", key)
    }
    
    let response = builder
        .body(enc_request)
        .send()
        .await?
        .error_for_status()?;

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
                output.write_all(&chunk)?;
            }
            Err(e) => {
                println!("Error in stream {}", e)
            }
        }
    }
    Ok(())
}
