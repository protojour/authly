fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&["proto/test_grpc.proto"], &["proto/"])?;

    println!("cargo:rerun-if-changed=build.rs");

    Ok(())
}
