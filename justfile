authly_id := "bf78d3c3bf94695c43b56540ffe23beace66ec53e35eee3f5be4c9a5cda70748"

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
        AUTHLY_DOCUMENT_PATH="[examples/demo/]" \
        AUTHLY_DATA_DIR=.local/data \
        AUTHLY_ETC_DIR=.local/etc \
        AUTHLY_EXPORT_TLS_TO_ETC=true \
        AUTHLY_BAO_TOKEN=theenigmaticbaobunofancientsecrets \
        AUTHLY_BAO_URL=http://localhost:8200 \
            cargo run -p authly --features dev configure
    fi

debug_web_port := "12345"

# run debug version on localhost. Necessary for running end-to-end tests.
rundev: dev-environment generate-testdata
    AUTHLY_ID={{ authly_id }} \
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

# clean up data files used for local run
cleanlocal:
    -rm -r .local

# run end2end tests, these are dependent on `rundev` running in the background
end2end:
    cargo test -- --include-ignored

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

# build protojour/authly:dev debug image
dev-image: musl
    docker build . -t protojour/authly:dev --platform linux/amd64 --build-arg RUST_PROFILE=debug

# build protojour/authly-testservice:dev image
testservice-image:
    cross build -p authly-testservice --target x86_64-unknown-linux-musl --target-dir target-musl
    docker build . -f testservice.Dockerfile -t protojour/authly-testservice:dev

# deploy local development version of authly to authly-test k8s namespace. Cluster should be a k3d cluster running k3d-registry-dockerd.
k8s-test-deploy: generate-testdata dev-image testservice-image k8s-test-setup
    kubectl apply -f testfiles/k8s/authly.yaml
    kubectl apply -f testfiles/k8s/testservice.yaml
    kubectl apply -f testfiles/k8s/arx.yaml
    kubectl apply -f testfiles/k8s/routing.yaml

    kubectl delete pods --namespace=authly-test -l 'app=authly' &
    kubectl delete pods --namespace=authly-test -l 'app=testservice' &
    kubectl delete pods --namespace=authly-test -l 'app=arx' &
    wait

# rebuild authly and restart its kubernetes pods
k8s-test-refresh-authly: dev-image
    kubectl delete pods --namespace=authly-test -l 'app=authly'

# rebuild testservice and restart its kubernetes pods
k8s-test-refresh-testservice: testservice-image
    kubectl delete pods --namespace=authly-test -l 'app=testservice'

# create the authly-test namespace and create basic configmaps and secrets
k8s-test-setup:
    -kubectl create namespace authly-test

    kubectl create secret tls authly-cluster-key \
        -n authly-test \
        --cert=.local/etc/cluster-k8s/tls.crt \
        --key=.local/etc/cluster-k8s/tls.key \
        -o yaml \
        --dry-run=client \
        | kubectl apply -f -

    kubectl create configmap authly-documents \
        -n authly-test \
        --from-file=examples/demo/ \
        -o yaml \
        --dry-run=client \
        | kubectl apply -f -

docker-test: generate-testdata dev-image testservice-image
    RUST_PROFILE=debug docker compose -f testfiles/docker/docker-compose.yml up
