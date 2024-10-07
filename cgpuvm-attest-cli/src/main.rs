use cgpuvm_attest::attest;
use std::env;

pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Usage: {} <maa_url>", args[0]);
    }
    let maa_url = &args[1];

    let s = "{\"a\":1}";
    let Some(token) = attest(s.as_bytes(), 0xffff, &maa_url) else {panic!("Failed to get MAA token")};
    println!("Got MAA token: {}", String::from_utf8(token).unwrap());
}
