use clap::Parser;

use rayon::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Brute force
    #[arg(short, long, action)]
    force: bool,

    /// Bcrypt hash
    #[arg(short, long, action)]
    bcrypt: bool,

    /// MD5 hash
    #[arg(short, long, action)]
    md5: bool,

    /// The possible largest length the raw password string can be.
    /// Note that this will take a long time!
    #[arg(short, long, default_value_t = 6)]
    password_length: u8,

    #[arg(short, long)]
    input: String,
}

enum HashType {
    BCrypt,
    MD5,
}

/// Generator for a character cartesian product.
struct AllStringIter(String, u8);

impl AllStringIter {
    fn new(n: u8) -> Self {
        Self(String::new(), n)
    }
}

impl Iterator for AllStringIter {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let mut i = self.0.len();
        while let Some('z') = self.0.chars().last() {
            self.0.pop();
        }

        if self.0.is_empty() {
            i += 1
        } else {
            let c = self.0.pop().unwrap();
            self.0.push(std::char::from_u32(c as u32 + 1).unwrap());
        }

        if i == (self.1 + 1) as usize {
            return None;
        }

        while self.0.len() < i {
            self.0.push('a');
        }

        Some(self.0.clone())
    }
}

/// executes an iter using `AllStringIter` in parallel using `rayon`.
fn compare(predicate: fn(&str, &str) -> bool, len: u8, hash: &str) -> Option<String> {
    AllStringIter::new(len)
        .par_bridge()
        .find_map_first(|f| match predicate(&f, hash) {
            true => Some(f),
            false => None,
        })
}

/// takes all `types` and performs a brute force attack using each, returning the result.
fn brute(hashtype: HashType, hash: String, len: u8) -> Option<String> {
    match hashtype {
        HashType::MD5 => compare(|x, y| format!("{:?}", md5::compute(x)) == y, len, &hash),
        HashType::BCrypt => compare(
            |x, y| bcrypt::verify(x, y).expect("Input hash was not proper bcrypt hash."),
            len,
            &hash,
        ),
    }
}

fn main() {
    let args = Args::parse();

    let out = match (args.md5, args.bcrypt) {
        (false, true) => brute(HashType::BCrypt, args.input, args.password_length),
        (true, false) => brute(HashType::MD5, args.input, args.password_length),
        _ => panic!("Please specify either -b or -m"),
    };

    match out {
        Some(x) => println!("Found hash {x}"),
        None => println!("Hash not found."),
    }
}
