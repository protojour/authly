fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=update.sh");
    println!("cargo:rerun-if-changed=static/vendor");

    std::process::Command::new("sh")
        .arg("update.sh")
        .output()
        .expect("failed to run update script");

    Ok(())
}
