FROM scratch AS dist
COPY target-musl/x86_64-unknown-linux-musl/debug/authly-testservice /authly-testservice

ENTRYPOINT ["/authly-testservice"]
CMD ["--help"]
