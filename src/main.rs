use std::io::stdin;

mod decode;

use decode::{print_colored, read_jwt};

fn main() {
    let mut input = String::new();
    stdin().read_line(&mut input).expect("No input provided");

    let jwt = match read_jwt(&input) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    print_colored(jwt);
}
