generate-testdata:
    #!/usr/bin/env bash
    if ! test -f test/cluster.crt; then
        cargo run -p authly issue-cluster-key --out-path test

        AUTHLY_DATA_DIR=./test/.data \
        AUTHLY_CLUSTER_CERT_FILE=./test/cluster.crt \
        AUTHLY_CLUSTER_KEY_FILE=./test/cluster.key \
            cargo run -p authly issue-service-identity --eid 272878235402143010663560859986869906352 --out test/testservice-identity.pem
    fi

rundev: generate-testdata
    cargo run -p authly issue-cluster-key --out-path test

    AUTHLY_HOSTNAME=localhost \
    AUTHLY_DATA_DIR=./test/.data \
    AUTHLY_CLUSTER_CERT_FILE=./test/cluster.crt \
    AUTHLY_CLUSTER_KEY_FILE=./test/cluster.key \
    AUTHLY_EXPORT_LOCAL_CA=./test/exported-local-ca.pem \
        cargo run -p authly serve

# default target
target := "x86_64-unknown-linux-musl"

# build musl binaries
musl *flags:
    #!/usr/bin/env bash
    if ! command -v cross 2>&1 >/dev/null; then
        echo note: cross not installed, using cargo
        buildcmd='cargo'
    elif [[ -z "${AUTHLY_NOCROSS}" ]]; then
        echo note: cross is installed, set AUTHLY_NOCROSS=1 to disable
        buildcmd='cross'
    else
        buildcmd='cargo'
    fi

    $buildcmd build -p authly {{ flags }} --target {{ target }} --target-dir target-musl

dev-image: musl
    docker build . -t situ/authly:dev --platform linux/amd64 --build-arg RUST_PROFILE=debug

testservice:
    cross build -p authly-testservice --target x86_64-unknown-linux-musl --target-dir target-musl
    docker build . -f testservice.Dockerfile -t situ/authly-testservice:dev

kubernetes-test-deploy: generate-testdata dev-image testservice
    -kubectl create namespace authly-test
    -kubectl create secret tls authly-cluster-key -n authly-test --cert=test/cluster.crt --key=test/cluster.key
    kubectl apply -f test/k8s/authly.yaml
    kubectl apply -f test/k8s/testservice.yaml

    kubectl delete pods --namespace=authly-test -l 'app=authly'
    kubectl delete pods --namespace=authly-test -l 'app=testservice'
