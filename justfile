authly_id := "bf78d3c3bf94695c43b56540ffe23beace66ec53e35eee3f5be4c9a5cda70748"
debug_web_port := "12345"

# default target
target := "x86_64-unknown-linux-musl"

# run debug version on localhost. Necessary for running end-to-end tests.
rundev: dev-environment generate-testdata
    AUTHLY_ID={{ authly_id }} \
    AUTHLY_LOG=info \
    AUTHLY_DOCUMENT_PATH="[examples/demo/]" \
    AUTHLY_HOSTNAME=localhost \
    AUTHLY_SERVER_PORT=1443 \
    AUTHLY_DATA_DIR=.local/data \
    AUTHLY_ETC_DIR=.local/etc \
    AUTHLY_BAO_TOKEN=theenigmaticbaobunofancientsecrets \
    AUTHLY_BAO_URL=http://localhost:8200 \
    AUTHLY_DEBUG_WEB_PORT={{ debug_web_port }} \
        cargo run -p authly --features dev serve

# run release version on localhost
runrelease: dev-environment generate-testdata
    AUTHLY_ID={{ authly_id }} \
    AUTHLY_DOCUMENT_PATH="[examples/demo/]" \
    AUTHLY_HOSTNAME=localhost \
    AUTHLY_SERVER_PORT=1443 \
    AUTHLY_DATA_DIR=.local/data \
    AUTHLY_ETC_DIR=.local/etc \
    AUTHLY_BAO_TOKEN=theenigmaticbaobunofancientsecrets \
    AUTHLY_BAO_URL=http://localhost:8200 \
        cargo run --release -p authly serve

# setup docker dev environment
dev-environment:
    docker-compose -f docker-compose.dev.yml up -d

# generate files necessary for running authly locally
generate-testdata:
    #!/usr/bin/env bash
    if ! test -d .local; then
        mkdir .local
        AUTHLY_ID={{ authly_id }} \
        AUTHLY_ETC_DIR=.local/etc \
        AUTHLY_HOSTNAME=localhost \
        AUTHLY_K8S=true \
        AUTHLY_BAO_TOKEN=theenigmaticbaobunofancientsecrets \
        AUTHLY_BAO_URL=http://localhost:8200 \
            cargo run -p authly --features dev issue-cluster-key

        AUTHLY_ID={{ authly_id }} \
        AUTHLY_LOG=info \
        AUTHLY_DOCUMENT_PATH="[examples/demo/]" \
        AUTHLY_DATA_DIR=.local/data \
        AUTHLY_ETC_DIR=.local/etc \
        AUTHLY_EXPORT_TLS_TO_ETC=true \
        AUTHLY_BAO_TOKEN=theenigmaticbaobunofancientsecrets \
        AUTHLY_BAO_URL=http://localhost:8200 \
            cargo run -p authly --features dev configure
    fi

# clean up data files used for local run
cleanlocal:
    -rm -r .local

# run end2end tests, these are dependent on `rundev` running in the background
end2end:
    cargo test -- --include-ignored

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

# build protojour/authly:dev debug image
dev-image: musl
    docker build . -t protojour/authly:dev --platform linux/amd64 --build-arg RUST_PROFILE=debug

# build protojour/authly-testservice:dev image
testservice-image:
    cross build -p authly-testservice --target x86_64-unknown-linux-musl --target-dir target-musl
    docker build . -f testservice.Dockerfile -t protojour/authly-testservice:dev

# deploy local development version of authly w/demo apps to authly-test k8s namespace. Cluster should be a k3d cluster running k3d-registry-dockerd.
k8s-demo-deploy: dev-image testservice-image
    # idempotent preparation
    -kubectl create namespace authly-test
    mkdir -p pkg/helm/authly-documents && cp examples/demo/* pkg/helm/authly-documents/
    kubectl apply -f testfiles/k8s/demo/openbao.yaml

    # (re-)deploy Authly using helm
    HELM_MAX_HISTORY=10 \
        helm upgrade --install authly pkg/helm/ \
        --namespace authly-test \
        -f testfiles/k8s/authly-test-values.yaml

    # (re-)deploy extra things for the demo
    kubectl apply \
        -f testfiles/k8s/demo/testservice.yaml \
        -f testfiles/k8s/demo/arx.yaml \
        -f testfiles/k8s/demo/routing.yaml

    # restart pods
    kubectl delete pods --namespace=authly-test -l 'authlyDev=restart' --wait=false

# rebuild authly and restart its kubernetes pods
k8s-refresh-authly: dev-image
    kubectl delete pods --namespace=authly-test -l 'app=authly'

# rebuild testservice and restart its kubernetes pods
k8s-refresh-testservice: testservice-image
    kubectl delete pods --namespace=authly-test -l 'app=testservice'

docker-test-deploy: generate-testdata dev-image testservice-image
    RUST_PROFILE=debug docker compose -f testfiles/docker/docker-compose.yml up
