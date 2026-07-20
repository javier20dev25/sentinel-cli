use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let name = if args.len() > 1 { &args[1] } else { "world" };
    println!("Hello, {}!", name);
    println!("This is a normal Rust CLI tool for demonstration");
}
