FROM scratch AS dist_amd64
ARG RUST_PROFILE
COPY target-musl/x86_64-unknown-linux-musl/$RUST_PROFILE/authly /authly

FROM scratch AS dist_arm64
ARG RUST_PROFILE
COPY target-musl/aarch64-unknown-linux-musl/$RUST_PROFILE/authly /authly

FROM dist_${TARGETARCH} AS dist
ARG TARGETARCH

ENTRYPOINT ["/authly"]
CMD ["--help"]
