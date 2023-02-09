use clap::Parser;
use itertools::Itertools;
use rayon::prelude::IntoParallelRefIterator;

use rayon::prelude::*;

static ALPHABET: [char; 26] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z',
];

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
    /// Defaults to 64
    #[arg(short, long, default_value_t = 3)]
    password_length: u8,

    #[arg(short, long)]
    input: String,
}

enum Method {
    Brute,
    Library,
}

enum HashType {
    BCrypt,
    MD5,
}

/// generates an alphabetical array of characters up to n characters long.
/// [a, b, ..., z, aa, ab, ..., az, ..., zz]
/// currently extraordinarily very inefficient
fn generate_alphabet_array_n(n: u8) -> Vec<String> {
    (1..n + 1)
        .flat_map(|i| {
            (0..i)
                .map(|_| ALPHABET.map(|c| String::from(c)))
                .multi_cartesian_product()
                .map(|p| p.join(""))
        })
        .collect::<Vec<String>>()
}

/// NOTE: Introduces a copy. Maybe RAM intensive for a short while.
fn compute_array_md5_hash(unhashed: &Vec<String>) -> Vec<(String, String)> {
    unhashed
        .par_iter()
        .map(|u| (u.to_owned(), format!("{:?}", md5::compute(u))))
        .collect::<Vec<(String, String)>>()
}

fn compare_hashes(hashed: &Vec<(String, String)>, to_find: &str) -> Option<String> {
    hashed.par_iter().find_map_first(|f| match f.1 == to_find {
        true => Some(f.0.clone()),
        false => None,
    })
}

/// takes all `types` and performs a brute force attack using each, returning the result.
fn brute(types: Vec<HashType>, hash: String, len: u8) -> Vec<Option<String>> {
    types.iter().map(|hashtype| match hashtype {
        HashType::MD5 => {
            let a = generate_alphabet_array_n(len);
            let h = compute_array_md5_hash(&a);
            compare_hashes(&h, &hash)
        }
        HashType::BCrypt => unimplemented!(),
    }).collect::<Vec<Option<String>>>()
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
