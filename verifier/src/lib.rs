
use base64::engine::general_purpose;
use serde::Deserialize;
use base64::{self, Engine};
use openssl::x509::X509;
use openssl::sign::Verifier;
use openssl::hash::{MessageDigest, Hasher};
use hex;
mod err;
pub use crate::err::Error;
pub use crate::err::Res;


#[derive(Deserialize)]
struct ProofElement {
    left: Option<String>,
    right: Option<String>
}

#[derive(Deserialize)]
struct LeafComponents {
    write_set_digest: String,
    commit_evidence: String,
    claims_digest: String,
}

#[derive(Deserialize)]
struct Receipt {
    signature: String,
    cert: String,
    node_id: String,
    is_signature_transaction: bool,
    leaf_components: LeafComponents,
    proof: Vec<ProofElement>
}

fn check_certificate(cert: &str, service_cert_pem: &str) -> Res<bool> {
    // Load the endorser certificate from PEM
    let service_cert = X509::from_pem(service_cert_pem.as_bytes())?;

    // Extract the public key from the endorser certificate
    let public_key = service_cert.public_key()?;

    // Load the endorsed certificate from PEM
    let endorsed_cert = X509::from_pem(cert.as_bytes())?;

    // Verify the endorsed certificate using the endorser's public key
    let result = endorsed_cert.verify(&public_key)?;
    
    Ok(result)
}

fn compute_leaf(leaf_components: LeafComponents) -> Res<Vec<u8>> {
    // Digest commit evidence
    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    hasher.update(leaf_components.commit_evidence.as_bytes())?;
    let mut commit_evidence_digest = hasher.finish()?.to_vec();

    println!("write_set_digest: {}", leaf_components.write_set_digest);
    println!("commit_evidence_digest: {}", hex::encode(&commit_evidence_digest));
    println!("claims_digest: {}", leaf_components.claims_digest);
    
    // Concatenate write_set_digest, commit_evidence_digest, and claims_digest
    let mut claims_digest_bytes = hex::decode(leaf_components.claims_digest.clone())?;
    let mut digests = hex::decode(leaf_components.write_set_digest.clone())?;
    digests.append(&mut commit_evidence_digest);
    digests.append(&mut claims_digest_bytes);

    // Compute leaf 
    let mut leaf_hasher = Hasher::new(MessageDigest::sha256())?;
    leaf_hasher.update(&digests)?;
    let leaf = leaf_hasher.finish()?.to_vec();
    Ok(leaf)
}

fn compute_root(proof: Vec<ProofElement>, leaf: Vec<u8>) -> Res<Vec<u8>> {
    let mut current = leaf;

    for n in proof {
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        if let Some(left) = n.left {
            hasher.update(&hex::decode(left)?)?;
            hasher.update(&current)?;
        } else if let Some(right) = n.right {
            hasher.update(&current)?;
            hasher.update(&hex::decode(right)?)?;
        }

        current = hasher.finish()?.to_vec();
    }

    Ok(current)
}

fn check_signature(signing_cert: &str, signature: &str, root: &[u8]) -> Res<bool> {
    // Load the certificate from PEM format
    let certificate = X509::from_pem(signing_cert.as_bytes())?;

    // Extract the public key from the certificate
    let public_key = certificate.public_key()?;

    // Create a verifier for the specific hash algorithm (e.g., SHA256)
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;

    // Feed the value to the verifier
    verifier.update(root)?;

    // Verify the signature
    let sig = general_purpose::STANDARD.decode(signature)?;

    println!("sig: {}", hex::encode(&sig));

    let is_valid = verifier.verify(&sig)?;
     
    Ok(is_valid)
}

/// Verify receipt from KMS
pub fn verify(receipt_str: &str, service_cert: &str) -> Res<bool> {
    let receipt: Receipt = serde_json::from_str(receipt_str)?;

    // Check that the certificate used to sign the receipt is endorsed by the KMS
    let mut result = check_certificate(&receipt.cert, service_cert)?;

    // Compute leaf
    let leaf = compute_leaf(receipt.leaf_components)?;

    println!("leaf: {}", hex::encode(&leaf));

    // Compute root using leaf and proof
    let root = compute_root(receipt.proof, leaf)?;

    println!("root: {}", hex::encode(&root));

    // Check signature over the root
    result = check_signature(&receipt.cert, &receipt.signature, root.as_slice())?;

    println!("Receipt verification passed?: {}", result);
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = verify(&"", &"").unwrap();
        assert_eq!(result, true);
    }
}