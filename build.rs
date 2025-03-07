fn main() {
    prost_build::compile_protos(&["src/NewTransactionResponse.proto"], &["src/"])
        .unwrap();
    println!("Proto compiled successfully");
}
