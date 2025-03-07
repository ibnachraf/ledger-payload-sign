use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use ecdsa::{
    signature::{self, Signer},
    Signature, SigningKey,
};
use k256::SecretKey;
use pem::parse;
use prost::Message;
use std::fs;

mod transaction {
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}

fn main() {
    // imagine a swap Bitcoin to USDT transaction
    let transaction_payload = transaction::NewTransactionResponse {
        payin_address: "0x1234567890".to_string(),
        payin_extra_id: "".to_string(),
        refund_address: "bcYYYYYYYYYYYYYY".to_string(),
        refund_extra_id: "".to_string(),
        payout_address: "bcXXXXXXXXXXXXXX".to_string(),
        payout_extra_id: "".to_string(),
        currency_from: "bitcoin".to_string(),
        currency_to: "ethereum/erc20/usdt".to_string(),
        amount_to_provider: 1_i32.to_be_bytes().to_vec(),
        amount_to_wallet: 80000_i32.to_be_bytes().to_vec(),
        device_transaction_id: "".to_string(),
        device_transaction_id_ng: "abc123".to_string().into_bytes(),
    };

    let mut buf_transaction_payload_binary = Vec::new();
    transaction_payload
        .encode(&mut buf_transaction_payload_binary)
        .expect("encode failed");

    let base_64 = URL_SAFE.encode(&buf_transaction_payload_binary);

    println!("Payload {}", base_64);

    ////////// Signing ///////////
    let pem_private_key = fs::read_to_string("sample-priv-key-p8.pem").expect("file not found");
    let pem = parse(&pem_private_key).expect("Failed to parse PEM");

    let secret_key = SecretKey::from_slice(&pem.contents).expect("Failed to parse secret key");

    let signing_key = SigningKey::from(secret_key);

    let signature: Signature<_> = signing_key.sign(&buf_transaction_payload_binary);
    let signature_base64url = URL_SAFE.encode(signature.to_bytes());

    println!("Signature {}", signature_base64url);
}
