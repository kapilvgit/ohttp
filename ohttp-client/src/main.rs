#![deny(clippy::pedantic)]

use bhttp::{Message, Mode};
use std::{
    fs::{self, File}, io::{self, Read, Write}, ops::Deref, path::PathBuf, str::FromStr
};
use std::io::Cursor;
use structopt::StructOpt;
use reqwest::Client;
use reqwest::header::AUTHORIZATION;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

const DEFAULT_KMS_URL: &str ="https://acceu-aml-504.confidential-ledger.azure.com";
const TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ikg5bmo1QU9Tc3dNcGhnMVNGeDdqYVYtbEI5dyIsImtpZCI6Ikg5bmo1QU9Tc3dNcGhnMVNGeDdqYVYtbEI5dyJ9.eyJhdWQiOiJodHRwczovL21sLmF6dXJlLmNvbSIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzMzZTAxOTIxLTRkNjQtNGY4Yy1hMDU1LTViZGFmZmQ1ZTMzZC8iLCJpYXQiOjE3MjczODMyMTMsIm5iZiI6MTcyNzM4MzIxMywiZXhwIjoxNzI3Mzg3NTgyLCJhY3IiOiIxIiwiYWlvIjoiQVdRQW0vOFhBQUFBOUdNS2RjNm4wZXZwdWlWaS92Z01yUEkyNUE5TG5NdkxST2tpeFNPdkJGMFBLMW9sTVYzWjZ0ZHRXSUdoNGJ3YVZIYVM5L0pZYkNhM3h6RFc1bW1yKy84akVHRSs4cEh0VDhXYTFoSzF5ZENnaEFDUldpUGxRL0lMQmhpbUIxbDciLCJhbXIiOlsicnNhIiwibWZhIl0sImFwcGlkIjoiZDczMDRkZjgtNzQxZi00N2QzLTliYzItZGYwZTI0ZTIwNzFmIiwiYXBwaWRhY3IiOiIwIiwiZGV2aWNlaWQiOiI2NWRjYWUwYi03NDI4LTQ1NWMtYjdhYS0yNTY1MDNhOTU0MzkiLCJmYW1pbHlfbmFtZSI6Ikdva2FybiIsImdpdmVuX25hbWUiOiJBcnRoaSIsImdyb3VwcyI6WyIyZjM4NDkwMC1kZTgwLTQ3OTYtOGQ4ZS03ODMyZjY1MmFlMjIiLCJlYmJlZjEwMi1lZDY1LTQzZjItYjcyYS04YzllMzRkNWYyYTgiLCJkMjE4YTMxNi1hNDg5LTQ0M2EtYTRhMC0yZTg5YzcwNDM0Y2MiLCJmOThlMWIxZC02OTc0LTQyZmItYTdjYi0zNmFkYzlmZWE1MGUiLCI2MDNkMDYyZC00ZGE1LTQzMGItODNhYS1kNmRkMmJmOTA2NzciLCJmOWIwMjgzMS02ZDZmLTQwNDktYWFiNC01ZWU2YzdjYTQ4MDIiLCIyNTkzYWUzNS04NDVjLTQyMWMtOThkOC1iNTIzODFkOGI2YWIiLCJiYmRlNWQzNy0yM2Q2LTQxZDUtOTA3MC0wNGQ1MDZiNzhiZjYiLCI4ZWRmYmYzOS1kMjg4LTQ1ZTUtODk3Mi00YzMzMzY3OGQ0NGEiLCI2NGY5OWM0Mi02M2U1LTRjYzAtOTJlZS0yOTUxNTEyOGEwMjciLCJlMjlkNjk1Mi0yYmFlLTRmZGEtYjdmZS00ZjdiZDJlNWM4NjIiLCJhYjhkNDY1NC0yZGFmLTQ0NjctYjVjOC04OGQ5NDBiNzQyMDUiLCI0Njk0NmI1NC1jZWM2LTRlNzQtOGE3My1kYzc0NWE3NjdiYzEiLCIyZjllNDM2Mi1hOWJlLTRkMzQtYjY5Mi0xYjc1M2Q3YjA4NDQiLCI5YzM4Mzc2My1kZmFkLTQ2NzEtYjRhMC1jNDYyYTEwMTg1NWYiLCJhOTE2Zjg2NC0wNzM0LTQ2N2YtYmE0Ni0zNjM5YjZkZjVhOGIiLCJmYmZjOTc2Ni0yYzMzLTRmOTUtYTE1MC0yYWNmYzM2YmVkMmYiLCI1ZjBlYjc2ZC1lNWM3LTQ0OTQtYTRhMC01MmMzMDg2YTQwYzEiLCJlYmVkMWM3Ni1hNmI4LTRlYjAtOWYwYS05YTdlZGE1ZjMwN2UiLCI3MzUyZjY4MC0zZWUxLTRkZGEtOTQwMS03NTU1M2E2MThlMGIiLCJiZWUwYmQ4Mi01YjQwLTQ0YjItYjYzNS02N2M4YTk0ODE5M2YiLCIwNTQ0Mzk4Ni0xY2ZhLTQ5NzMtYmZlMy00YjE0M2YzYmMyZjkiLCJmYzE5ZGE4Zi1jN2IxLTRiOGEtYTE0YS1kYTIyYjk0NjUzMmQiLCIyOTlhYjE5MC0yYjIxLTRmYjEtYTNiNS1lNTNiZGY3OTdjMWMiLCI2Zjg3NjI5Mi00OGZiLTQ2ZjktYTM2NC1hZjMwOGM4MzVkNmIiLCI5MGMzMDM5ZS05NWM4LTQyN2YtOGNlYy1lNGMxMGZmZDY2ZWQiLCJmYjExMDBhOS03NTNjLTQzNTQtODNkYi00OGFlMzU5MTAxOGYiLCI5YmFiOWViOC00YjYyLTQ5ZWUtYmM1ZC02NTRjNDA3YzJiMjMiLCIxODdhYzhjMS0wNmMwLTQ2YTItYjQ1NS03ZWI1ZDIyZmNiMjkiLCIwMjcyN2RjZC1mM2I4LTQ5ZjgtODQ2YS03Y2I5YzA5NjM5MzQiLCIzNjhjOTNjZS02NjBmLTQzNTgtYjBiYy1jYmM0YzEyNjcyODIiLCIzOThjMzRkOC04MWFlLTQxMTAtYjk0NS1iMmQwZTcxMWJmYzUiLCI0YmI1NDVlNy00NzgwLTRjMzItYWUwYi04MzNhNTlkYzc5ZjYiLCI5Y2VhNzdmNC05NzY4LTRiNzItOWU5NS00YWY5YTlmMDkwN2MiXSwiaWR0eXAiOiJ1c2VyIiwiaXBhZGRyIjoiMjAwMTo0ODk4OmIwODA6MDo3Zjk5OjoxNiIsIm5hbWUiOiJBcnRoaSBHb2thcm4gKEFSVEhJRykiLCJvaWQiOiI5ZDkzNTc1MS0yNzY4LTRjOWUtODYyOS05ZTkwZmYxMzY2YmMiLCJvbnByZW1fc2lkIjoiUy0xLTUtMjEtNDEyOTg2ODIyNS0xMzI4NTgxMTI2LTM4OTc1NzE0NDYtMTQ4ODM2IiwicHVpZCI6IjEwMDMyMDAyOTI5M0ZBRTUiLCJyaCI6IjAuQVRNQUlSbmdNMlJOakUtZ1ZWdmFfOVhqUFY5dnBoamYyeGRNbmRjV05IRXFuTDR6QURRLiIsInNjcCI6InVzZXJfaW1wZXJzb25hdGlvbiIsInN1YiI6Ijk0VTFKZTVLZ2UzSmtCLUNnbnAybVhLM3dXMTBsYUlORzJBd1VGTWxWUU0iLCJ0aWQiOiIzM2UwMTkyMS00ZDY0LTRmOGMtYTA1NS01YmRhZmZkNWUzM2QiLCJ1bmlxdWVfbmFtZSI6IkFSVEhJR0BhbWUuZ2JsIiwidXBuIjoiQVJUSElHQGFtZS5nYmwiLCJ1dGkiOiJDLUF3ek1Fem5raWRUT1B6UHVxVUFBIiwidmVyIjoiMS4wIiwieG1zX2lkcmVsIjoiMSAzMCJ9.V7jJ2T1loJx0e-AYChFJHyg5lHmtnGuTTLED1YKZHwpAXnc7BXcmcz4xVyPeKV9OIzAHCfNLjjgg_3pQtQwIBgt3yTmFnwPX6r1faccDGsNthfKQK1Y7BLxiM0jDC0P2UHfBcZShpks5RtqWOhwn-xc6xKW9zzONTS2SodlcHvKL9H3iJI2JyqZ-xyk23uRK9n-w9lfVb7LFYfxECsRDYeG3rwIs1qpggk4GOAVdhDjImsnfDk_ItM5bUE-PCwzv8F1a7x-JIt72fzrxFZmkPw9xgNUpfbjhoJiQzy6ZCLGnFXnjZLenCZTie_POIuPH4A7rdK9fnvHBA61i8WReZQ";

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

    /// When creating message/bhttp, use the indeterminate-length form.
    #[structopt(long, short = "n", alias = "indefinite")]
    indeterminate: bool,

    /// Enable override for the trust store.
    #[structopt(long)]
    trust: Option<PathBuf>,

    #[structopt(long, short = "a")]
    api_key: Option<String>
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
//accsingularity.azurecr.io/samples/ohttp-server:latest sha256:f6629aed9cc3683bc755e06baf720824cf7009c296fc1b831dafb4bf6e5f1737
// curl -vv http://127.0.0.1:5002/v1/engines/whisper/audio/transcriptions -H "Content-Type: multipart/form-data" -H"Openai-Internal-AuthToken: testtoken" -H "Openai-Internal-EnableAsrSupport: true" -F file="@./whatstheweatherlike.wav" -F model="whisper"

// Create a multi-part request from a file
fn create_multipart_request(target_path: &str, file: &PathBuf) -> Res<Vec<u8>> {
    // Define boundary for multipart
    let boundary = "----ConfidentialInferencingFormBoundary7MA4YWxkTrZu0gW";

    let mut request = Vec::new();
    // Start of the request
    write!(&mut request, "POST {} HTTP/1.1\r\n", target_path)?;
    
    // Headers
    write!(&mut request, "openai-internal-authtoken: \"testtoken\"\r\n")?;
    write!(&mut request, "openai-internal-enableasrsupport: \"true\"\r\n")?;
    write!(&mut request, "Content-Type: multipart/form-data; boundary={}\r\n", boundary)?;

    // Placeholder for Content-Length, will fill in later
    let content_length_pos = request.len();

    // Start of the body
    write!(&mut request, "\r\n")?; // Empty line to separate headers from body

    // File part
    write!(&mut request, "--{}\r\n", boundary)?;
    write!(&mut request, "Content-Disposition: form-data; name=\"file\"; filename=\"audio.mp3\"\r\n")?;
    write!(&mut request, "Content-Type: audio/mpeg\r\n\r\n")?;

    // Here you'd read the file and write its content to the request
    
    // Load audio file
    let mut file = File::open(file)?;
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents)?;
    request.append(&mut file_contents);
    // End of file part
    write!(&mut request, "\r\n--{}\r\n", boundary)?;

    // Model part
    write!(&mut request, "Content-Disposition: form-data; name=\"model\"\r\n\r\n")?;
    write!(&mut request, "whisper\r\n")?;

    // Closing boundary
    write!(&mut request, "--{}--\r\n", boundary)?;

    // Calculate Content-Length
    let content_length = request.len() - content_length_pos; 

    // Overwrite the placeholder with the real content length
    write!(&mut request, "Content-Length: {} \r\n", content_length)?;
    
    // At this point, `request` contains the complete HTTP request with multipart/form-data.

    // For demonstration, print the request
    println!("{:?}", String::from_utf8_lossy(&request));

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

    println!("\n================== STEP 1 ==================");

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

    println!("\n================== STEP 2 ==================");
    let (enc_request, mut ohttp_response) = ohttp_request.encapsulate(&request_buf)?;
    println!("Sending encrypted OHTTP request to {}: {}", args.url, hex::encode(&enc_request[0..60]));
    fs::write("enc_request.bin", &enc_request)?;

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
        .header("content-type", "message/ohttp-chunked-req")
        .header(AUTHORIZATION, format!("Bearer {}", TOKEN))
        .header("azureml-model-deployment", "arthig-deploy15");

    if let Some(key) = &args.api_key {
        builder = builder.header("api-key", key)
    }
    
    let mut response = builder
        .body(enc_request)
        .send()
        .await?
        .error_for_status()?;

    let mut output: Box<dyn io::Write> = if let Some(outfile) = &args.output {
        Box::new(File::open(outfile)?)
    } else {
        Box::new(std::io::stdout())
    };

    let response_nonce = response.chunk().await?.unwrap();
    ohttp_response.set_response_nonce(&response_nonce)?;

    loop {
        match response.chunk().await? {
            Some(chunk) => {
                println!("Decrypting OHTTP chunk: {}\n", hex::encode(&chunk[0..60]));
                let (response_buf, last) = 
                    ohttp_response.decapsulate_chunk(&chunk);

                let buf = response_buf.unwrap();
                let response = Message::read_bhttp(&mut std::io::Cursor::new(&buf[..]))?;
                if args.binary {
                    response.write_bhttp(args.mode(), &mut output)?;
                } else {
                    output.write_all(response.content())?;
                }

                if last {
                    break;
                }
            }
            None => {
                break;
            }
        }
    }
    Ok(())
}
