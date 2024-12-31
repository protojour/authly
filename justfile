export AUTHLY_DATA_DIR := "./test/.data"
export AUTHLY_CERT_FILE := "./test/cert.pem"
export AUTHLY_KEY_FILE := "./test/cert.key.pem"

rundev:
    cargo run -p authly
