# Generate private public key
1. `openssl ecparam -name secp256r1 -genkey -noout -out sample-priv-key.pem`
2. `openssl ec -in sample-ledger-priv-key.pem -pubout > sample-pub-key.pem`
3. `openssl pkcs8 -topk8 -nocrypt -in sample-ledger-priv-key.pem -out sample-priv-key-p8.pem`
