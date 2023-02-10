# Thrash

A copy-cat `hashcat` utility implemented semi-functionally.

## How to use

### Display all options
`thrash -h`

### Crack MD5 hash
`thrash -i "5d41402abc4b2a76b9719d911017c592" -m -f -p 5`

`thrash -i '$2a$12$6QPHRjGYx0gqs2mgvwQvUuT6eCsiNZtEER5R/wZtAyqOoJuHNpW72' -b -f -p 5`

## Tech Stack
- `md5`
- `bcrypt`
- `rayon` for parallel programming.