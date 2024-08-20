#![deny(clippy::pedantic)]

use bhttp::{Message, Mode};
use std::{fs::File, io::{self, Read, Write}, ops::Deref, path::PathBuf, str::FromStr};
use structopt::StructOpt;
use std::path::Path;
use reqwest::multipart::{Form, Part};
use reqwest::multipart;
// use reqwest::blocking::Client;




type Res<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
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
    /// A hexadecimal version of the key configuration for the target URL.
    config: HexArg,

    /// Where to read request content.
    /// If you omit this, input is read from `stdin`.
    #[structopt(long, short = "i")]
    input: Option<PathBuf>,

    #[structopt(long, short = "a")]
    audio: Option<PathBuf>,

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

#[tokio::main]
async fn main() -> Res<()> {
    let args = Args::from_args();
    ::ohttp::init();
    env_logger::try_init().unwrap();

    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW1";
    
    //audio
    // let file_content = std::fs::read("./examples/whatstheweatherlike.wav").expect("Failed to read file");

    let file_content = if let Some(infile) = &args.audio {
        std::fs::read(infile).expect("Failed to read file")
    } else {
        println!("No audio file provided");
        Vec::new() 
    };

    let mut audio = Vec::new();
    write!(audio,
        "--{}\r\n\
         Content-Disposition: form-data; name=\"audio_file\"; filename=\"audio.wav\"\r\n\
         Content-Type: audio/wav\r\n\r\n",
        boundary).unwrap();
        audio.extend_from_slice(&file_content);
    write!(audio, "\r\n").unwrap();

    // Final boundary
    let mut final_boundary = Vec::new();
    write!(final_boundary, "--{}--\r\n", boundary).unwrap();

    let mut request_body = Vec::new();
    request_body.extend_from_slice(&audio);
    request_body.extend_from_slice(&final_boundary);



    // let tmp = request_body.clone();
    // println!("Tien print request_body : {:?}", request_body);

    // let client = reqwest::ClientBuilder::new().build()?;
    // let response = client
    //     .post("http://localhost:9000/asr?output=json")
    //     .header("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW1")
    //     .body(request_body)
    //     .send()
    //     .await?
    //     .error_for_status()?; 
    
    // let body = response.text().await?;
    // println!("Tien print Response Body111111: {}", body);

    let ohttp_request = ohttp::ClientRequest::from_encoded_config_list(&args.config)?;
    let (enc_request, mut ohttp_response) = ohttp_request.encapsulate(&request_body)?;


    
    // //Tien start
    // // Specify the file path
    // let file_path = Path::new("./examples/whatstheweatherlike.wav");

    // // Open the audio file
    // let mut file = File::open(&file_path)?;
    // let mut file_contents = Vec::new();
    // file.read_to_end(&mut file_contents)?;

    // // Create a multipart form
    // let part = Part::bytes(file_contents)
    //     .file_name(file_path.file_name().unwrap().to_string_lossy())
    //     .mime_str("audio/wav")?;

    // let form = Form::new().part("audio_file", part);
    // println!("Tien print form: {:?}", form);

    // Create a client
    // let client1 = reqwest::Client::new();
    // // Send the POST request with the file
    // let response1 = client1
    //     .post("http://localhost:9000/asr?output=json")
    //     .multipart(form)
    //     .send()
    //     .await?;
    // // Print the response
    // // println!("Response: {:?}", response1);
    // let body = response1.text().await?;
    // println!("Tien print Response Body: {}", body);
    // //Tien end










    // let request = if let Some(infile) = &args.input {
    //     let mut r = io::BufReader::new(File::open(infile)?);
    //     if args.binary {
    //         Message::read_bhttp(&mut r)?
    //     }         
    //     else {
    //         Message::read_http(&mut r)?
    //     }
    // } else {
    //     let mut buf = Vec::new();
    //     std::io::stdin().read_to_end(&mut buf)?;
    //     let mut r = io::Cursor::new(buf);
    //     if args.binary {
    //         Message::read_bhttp(&mut r)?
    //     } else {
    //         Message::read_http(&mut r)?
    //     }
    // };


    // let mut request_buf = Vec::new();
    // request.write_bhttp(Mode::KnownLength, &mut request_buf)?;//Tien: request_buf is binary encoded by UTF-8, why it is write_bhttp here? How the server is going to handle this?  
    // // logic in the server to handle this: let bin_request = Message::read_bhttp(&mut Cursor::new(&request[..]))?; 
  
    // let ohttp_request = ohttp::ClientRequest::from_encoded_config_list(&args.config)?;
    // let (enc_request, mut ohttp_response) = ohttp_request.encapsulate(&request_buf)?;



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
        None => reqwest::ClientBuilder::new().build()?,
    };

    // println!("Tien print enc_request: {:?}", &enc_request);
    // println!("Tien print enc_request: {}", hex::encode(&enc_request));

    let mut response = client
        .post(&args.url) //Tien: https://localhost:9443/score
        .header("content-type", "message/ohttp-chunked-req") //Tien: what is the impact of ohttp-chunked-req ?
        .body(enc_request) //Tien: encrypted content of the request.txt file
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
                // println!("====================================Tien print decapsulating {}, {}", chunk.len(), hex::encode(&chunk));                
                let (response_buf, last) = ohttp_response.decapsulate_chunk(&chunk);


                // println!("======================================================Tien is here 1 print response_buf {:?}", &response_buf);
                let buf = response_buf.unwrap();
                // println!("======================================================Tien is here 2");


                let response = Message::read_bhttp(&mut std::io::Cursor::new(&buf[..]))?;
                if args.binary {
                    response.write_bhttp(args.mode(), &mut output)?;
                } else {
                    response.write_http(&mut output)?;
                }
                if last { break; }
            }
            None => {
                break;
            }
        }    
    }
    Ok(())
}
