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

        if i == (self.1+1) as usize  {
            return None;
        }

        while self.0.len() < i {
            self.0.push('a');
        }

        Some(self.0.clone())
    }
}

/// takes all `types` and performs a brute force attack using each, returning the result.
fn brute(types: Vec<HashType>, hash: String, len: u8) -> Vec<Option<String>> {
    types
        .iter()
        .map(|hashtype| match hashtype {
            HashType::MD5 => AllStringIter::new(len).par_bridge().find_map_first(|f| {
                match format!("{:?}", md5::compute(&f)) == hash {
                    true => Some(f),
                    false => None,
                }
            }),
            HashType::BCrypt => {
                AllStringIter::new(len).par_bridge().find_map_first(|f| {
                    match bcrypt::verify(&f, &hash).unwrap() {
                        true => Some(f),
                        false => None,
                    }
                })
            },
        })
        .collect::<Vec<Option<String>>>()
}

fn main() {
    let args = Args::parse();

    let mut hash_types = vec![];
    if args.bcrypt {
        hash_types.push(HashType::BCrypt);
    }

    if args.md5 {
        hash_types.push(HashType::MD5);
    }

    if args.force {
        let results = brute(hash_types, args.input, args.password_length);

        println!("{:?}", results)
    }
}
