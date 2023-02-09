# Thrash

A copy-cat `hashcat` utility.

## How to use

### Display all options
`thrash -h`

### Crack MD5 hash
`thrash -i "4124bc0a9335c27f086f24ba207a4912" -m -f`

## Tech Stack
- `md5`
- `bcrypt`
- `rayon` for parallel programming.