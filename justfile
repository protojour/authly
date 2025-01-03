rundev:
    AUTHLY_HOSTNAME=localhost \
    AUTHLY_DATA_DIR=./test/.data \
    AUTHLY_CLUSTER_CERT_FILE=./test/cluster.pem \
    AUTHLY_CLUSTER_KEY_FILE=./test/cluster.key.pem \
    AUTHLY_EXPORT_LOCAL_CA=./test/exported-local-ca.pem \
        cargo run -p authly serve

generate_testdata:
    AUTHLY_DATA_DIR=./test/.data \
    AUTHLY_CLUSTER_CERT_FILE=./test/cluster.pem \
    AUTHLY_CLUSTER_KEY_FILE=./test/cluster.key.pem \
        cargo run -p authly issue-service-identity --eid 272878235402143010663560859986869906352 --out test/testservice-identity.pem

# default target
target := "x86_64-unknown-linux-musl"

# build musl binaries
musl *flags:
    #!/usr/bin/env bash
    if ! command -v cross 2>&1 >/dev/null; then
        echo note: cross not installed, using cargo
        buildcmd='cargo'
    elif [[ -z "${NOCROSS}" ]]; then
        echo note: cross is installed, set NOCROSS=1 to disable
        buildcmd='cross'
    else
        buildcmd='cargo'
    fi

    $buildcmd build -p authly {{ flags }} --target {{ target }} --target-dir target-musl

dev-image: musl
    docker build . -t situ/authly:dev --platform linux/amd64 --build-arg RUST_PROFILE=debug
