# Generate private public key
1. `openssl ecparam -name secp256k1 -genkey -noout -out sample-priv-key.pem`
2. `openssl ec -in sample-priv-key.pem -pubout > sample-pub-key.pem`
3. `openssl pkcs8 -topk8 -nocrypt -in sample-priv-key.pem -out sample-priv-key-p8.pem`
