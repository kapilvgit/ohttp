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
    // println!("Tien print args: {:?}", &args);

    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";

    // Part 2: File field
    let file_content = std::fs::read("./examples/whatstheweatherlike.wav").expect("Failed to read file");
    let mut part2 = Vec::new();
    write!(part2,
        "--{}\r\n\
         Content-Disposition: form-data; name=\"audio_file\"; filename=\"audio.wav\"\r\n\
         Content-Type: audio/wav\r\n\r\n",
        boundary).unwrap();
    part2.extend_from_slice(&file_content);
    write!(part2, "\r\n").unwrap();

    // Final boundary
    let mut final_boundary = Vec::new();
    write!(final_boundary, "--{}--\r\n", boundary).unwrap();

    // Combine all parts into a single request body
    let mut request_body = Vec::new();
    // request_body.extend_from_slice(&part1);
    request_body.extend_from_slice(&part2);
    request_body.extend_from_slice(&final_boundary);

    // Here `request_body` contains the serialized multipart request.
    // You can print it as a string or send it in an HTTP request.
    // println!("Tien print request_body {}", String::from_utf8_lossy(&request_body));


    let client = reqwest::ClientBuilder::new().build()?;
    // let tmp = request_body;
    let response = client
        .post("http://localhost:9000/asr?output=json")
        .header("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW")
        .body(request_body)
        .send()
        .await?
        .error_for_status()?; 
    
    // println!("Tien print Response: {:?}", response.text());
    let body = response.text().await?;
    println!("Tien print Response Body111111: {}", body);


    // let ohttp_request = ohttp::ClientRequest::from_encoded_config_list(&args.config)?;
    // let (enc_request, mut ohttp_response) = ohttp_request.encapsulate(&tmp)?;//Tien: what is this? encypted using hpke: let enc = self.hpke.enc()?; enc_request.extend_from_slice(&enc);




    // // Open the audio file
    // let mut file = File::open("./examples/whatstheweatherlike.wav")?;
    // // Create a buffer to hold the binary data
    // let mut buffer = Vec::new();
    // // Read the file into the buffer
    // file.read_to_end(&mut buffer)?;
    // // At this point, `buffer` contains the binary data of the file
    // println!("Tien print Binary data of the audio1: {:?}", &buffer);

    // // // let mut fileOut = File::create("./examples/whatstheweatherlikeOut.wav")?;
    // // // fileOut.write_all(&buffer)?;


    // // println!("Tien print Binary data of the audio3: {}", hex::encode(&buffer));

    // let hex_value = hex::encode(&buffer);
    // // println!("Tien print Binary data of the audio3: {}", hex_value);
    // let buffer2 = hex::decode(hex_value)?;
    // println!("Tien print Binary data of the audio2: {:?}", &buffer2);






    
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



    // let response = client
    // .request(method, t)
    // .headers(headers)
    // .body(enc-content) // client - to server: content is encrypted by hpke key. 1) From clear-content from the the curl.., 2) encrypt it to enc-content
    // .send()
    // .await?
    // .error_for_status()?;










    let request = if let Some(infile) = &args.input {
        let mut r = io::BufReader::new(File::open(infile)?);
        

        if args.binary {
            // println!("Tien is here1");
            Message::read_bhttp(&mut r)?
        } 
        
        else {
            // println!("Tien is here2");
            Message::read_http(&mut r)?
        }


    }   
    else {
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
    request.write_bhttp(Mode::KnownLength, &mut request_buf)?;//Tien: request_buf is binary encoded by UTF-8, why it is write_bhttp here? How the server is going to handle this?  
    // logic in the server to handle this: let bin_request = Message::read_bhttp(&mut Cursor::new(&request[..]))?; 



    // let mut request_buf2 = Vec::new();
    // request.write_http(&mut request_buf2)?;//Tien: this produce same result as file.read_to_end(&mut buffer)?;
    // // At this point, `buffer` contains the binary data of the file
    // println!("Tien print Binary data of the audio2: {:?}", request_buf2);   


    // let mut request_buf2 = Vec::new();
    // request.read_to_end(&mut request_buf2)?;
    // // At this point, `buffer` contains the binary data of the file
    // println!("Tien print Binary data of the audio2: {:?}", request_buf2);   

    


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



    
    // // Convert the form to bytes (this is done internally by reqwest when sending)
    // let mut form_bytes: Vec<u8> = Vec::new();
    // {
    //     let mut form_part = form.send_stream();
    //     while let Some(chunk) = form_part.next().await {
    //         form_bytes.extend_from_slice(&chunk?);
    //     }
    // }
    
    // // Now `form_bytes` contains the form data as a vector of bytes
    // println!("Form data as bytes: {:?}", form_bytes);





    let ohttp_request = ohttp::ClientRequest::from_encoded_config_list(&args.config)?;
    let (enc_request, mut ohttp_response) = ohttp_request.encapsulate(&request_buf)?;//Tien: what is this? encypted using hpke: let enc = self.hpke.enc()?; enc_request.extend_from_slice(&enc);
    // println!("Request: {}", hex::encode(&enc_request));

    // println!("=================================================================");
    // println!("Tien print enc_request: {:?}", &enc_request);
   


    


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

   

    
    // println!("Tien print response in the client: {:?}", &response);
    let response_nonce = response.chunk().await?.unwrap();
    ohttp_response.set_response_nonce(&response_nonce)?;
    

    loop {
        match response.chunk().await? {
            Some(chunk) => {
                // println!("Decapsulating {}, {}", chunk.len(), hex::encode(&chunk));

                
                let (response_buf, last) = ohttp_response.decapsulate_chunk(&chunk);//Tien: this is to decrypt using hpke.
                let buf = response_buf.unwrap();

                let response = Message::read_bhttp(&mut std::io::Cursor::new(&buf[..]))?;
                if args.binary {
                    // println!("Tien is here1: ");
                    response.write_bhttp(args.mode(), &mut output)?;
                } else {
                    // println!("Tien is here2: ");
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
